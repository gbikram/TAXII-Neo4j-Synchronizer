#!/usr/bin/env python3
"""
OpenCTI TAXII to Neo4j Synchronization Script

Synchronizes STIX data from a TAXII server to a Neo4j graph database, creating a 
graph representation of cyber threat intelligence data. It continuously polls the 
TAXII server and updates the Neo4j database with new threat intelligence.

The script creates nodes for STIX objects (like reports, indicators, threat actors)
and establishes relationships between them based on STIX relationships and report
references. This graph structure enables complex threat intelligence queries and
relationship analysis in Neo4j.
"""

import time
from stix2 import parse
from neo4j import GraphDatabase
import requests
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# === CONFIGURATION ===
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "jason-nepal-antenna-version-montana-4131"

# TAXII Configuration
TAXII_BASE_URL = "http://localhost:8080/opencti/taxii2/root/collections/0e40e6df-709d-448e-92de-ab970be4c00f/objects"

POLL_INTERVAL_SECONDS = 10  # how often to poll TAXII in seconds

# === NEO4J HELPER ===
class Neo4jHandler:
    def __init__(self, uri, user, password):
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            logger.info("Successfully connected to Neo4j database")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {str(e)}")
            raise

    def close(self):
        self.driver.close()

    def load_stix_object(self, stix_obj):
        try:
            with self.driver.session() as session:
                obj_type = stix_obj.get("type", "")
                
                # Skip creating nodes for relationship objects
                if obj_type != "relationship":
                    # Create the main node
                    logger.info(f"Processing STIX object of type: {stix_obj.get('type')} with ID: {stix_obj.get('id')}")
                    session.execute_write(self._create_node, stix_obj)
                
                # Handle report references
                if obj_type == "report" and "object_refs" in stix_obj:
                    logger.info(f"Processing report relationships for {stix_obj.get('id')}")
                    for ref_id in stix_obj["object_refs"]:
                        try:
                            session.execute_write(self._create_relationship, stix_obj["id"], ref_id, "REFERENCES")
                        except Exception as e:
                            logger.error(f"Error creating report reference relationship: {str(e)}")
                
                # Handle STIX Relationship Objects
                elif obj_type == "relationship":
                    source_ref = stix_obj.get("source_ref")
                    target_ref = stix_obj.get("target_ref")
                    relationship_type = stix_obj.get("relationship_type", "RELATED_TO").upper()
                    
                    if source_ref and target_ref:
                        logger.info(f"Processing relationship: {source_ref} -{relationship_type}-> {target_ref}")
                        try:
                            session.execute_write(
                                self._create_stix_relationship,
                                source_ref,
                                target_ref,
                                relationship_type,
                                stix_obj.get("id"),
                                {k: v for k, v in stix_obj.items() if isinstance(v, (str, int, float, bool))}
                            )
                        except Exception as e:
                            logger.error(f"Error creating STIX relationship: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing STIX object: {str(e)}")
            logger.error(f"Problematic STIX object: {stix_obj}")

    @staticmethod
    def _create_node(tx, obj):
        labels = [obj.get("type", "STIXObject").replace('-', '_')]
        props = {k: v for k, v in obj.items() if isinstance(v, (str, int, float, bool))}
        query = f"""
        MERGE (n:{':'.join(labels)} {{ id: $id }})
        SET n += $props
        """
        tx.run(query, id=obj["id"], props=props)

    @staticmethod
    def _create_relationship(tx, source_id, target_id, rel_type):
        # Sanitize relationship type to be Neo4j compliant
        rel_type = rel_type.replace('-', '_').replace(' ', '_')
        query = f"""
        MATCH (source {{id: $source_id}})
        MATCH (target {{id: $target_id}})
        MERGE (source)-[r:{rel_type}]->(target)
        """
        tx.run(query, source_id=source_id, target_id=target_id)

    @staticmethod
    def _create_stix_relationship(tx, source_id, target_id, rel_type, relationship_id, props):
        # Sanitize relationship type to be Neo4j compliant
        rel_type = rel_type.replace('-', '_').replace(' ', '_')
        query = f"""
        MATCH (source {{id: $source_id}})
        MATCH (target {{id: $target_id}})
        MERGE (source)-[r:{rel_type} {{id: $relationship_id}}]->(target)
        SET r += $props
        """
        tx.run(query, 
            source_id=source_id,
            target_id=target_id,
            relationship_id=relationship_id,
            props=props
        )

# === MAIN LOGIC ===
def fetch_stix_objects():
    """Fetch STIX objects from TAXII server with pagination support."""
    all_objects = []
    current_url = TAXII_BASE_URL

    while current_url:
        logger.info(f"Fetching STIX data from: {current_url}")
        response = requests.get(current_url).json()
        
        # Add objects from current page
        if 'objects' in response:
            all_objects.extend(response['objects'])
            
        # Check for more pages using 'more' and 'next' fields
        has_more = response.get('more', False)
        next_token = response.get('next')
        
        if has_more and next_token:
            current_url = f"{TAXII_BASE_URL}?next={next_token}"
        else:
            current_url = None
            
        logger.info(f"Fetched {len(response.get('objects', []))} objects from current page")
        
    logger.info(f"Total objects fetched: {len(all_objects)}")
    return {'objects': all_objects}


def main():
    """Main execution loop for TAXII to Neo4j synchronization."""
    logger.info("Starting TAXII to Neo4j synchronization...")
    
    # Initialize Neo4j connection
    try:
        neo4j = Neo4jHandler(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
    except Exception as e:
        logger.error(f"Failed to initialize Neo4j handler: {str(e)}")
        return

    try:
        # Main polling loop - continuously fetch and process STIX data
        while True:
            try:
                # Step 1: Fetch all STIX objects from TAXII server (with pagination)
                stix_objects = fetch_stix_objects()
                logger.info(f"Processing {len(stix_objects['objects'])} STIX objects.")

                # Step 2: Process each STIX object
                for obj in stix_objects['objects']:
                    try:
                        # Create nodes and relationships in Neo4j for each object
                        # - Creates nodes for non-relationship objects
                        # - Handles report references
                        # - Creates relationships between objects
                        neo4j.load_stix_object(obj)
                    except Exception as e:
                        # Continue processing other objects if one fails
                        logger.error(f"Error processing object: {str(e)}")
                        continue

                # Step 3: Wait for next polling interval
                logger.info(f"Sleeping for {POLL_INTERVAL_SECONDS} seconds...")
                time.sleep(POLL_INTERVAL_SECONDS)
            except Exception as e:
                # Handle any errors in the main loop and continue polling
                logger.error(f"Error in main loop: {str(e)}")
                time.sleep(POLL_INTERVAL_SECONDS)  # Still sleep before retrying
    finally:
        # Ensure Neo4j connection is properly closed on exit
        neo4j.close()
        logger.info("Shutting down...")

if __name__ == "__main__":
    main()

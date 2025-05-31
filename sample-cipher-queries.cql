//[Counts] Intrusion-Sets Shared Attack-Patterns
MATCH (i1:intrusion_set)-[:USES]->(attack:attack_pattern)<-[:USES]-(i2:intrusion_set)
WHERE id(i1) < id(i2)
WITH 
    i1, 
    i2, 
    collect({
        technique: attack.name,
        technique_id: attack.external_id,
        description: attack.description
    }) as shared_techniques
RETURN 
    i1.name as IntrusionSet1,
    i2.name as IntrusionSet2,
    size(shared_techniques) as NumberOfSharedTechniques,
    shared_techniques as SharedTechniques
ORDER BY NumberOfSharedTechniques DESC

===
  
//[Table] Shared Entities Between Reports
MATCH (r1:report)-[:REFERENCES]->(entity)<-[:REFERENCES]-(r2:report)
WHERE id(r1) < id(r2)
RETURN 
    r1.name as Report1,
    r2.name as Report2,
    entity.name as SharedEntity,
    entity.type as EntityType,
    datetime(r1.created) as Report1Created,
    datetime(r2.created) as Report2Created
ORDER BY Report1Created DESC

===
  
//Intrusion-Sets Shared Techniques
MATCH path = (i1:intrusion_set)-[:USES]->(attack:attack_pattern)<-[:USES]-(i2:intrusion_set)
WHERE id(i1) < id(i2)  // Prevent duplicate relationships
WITH i1, i2, attack, path
RETURN path
LIMIT 100
  
===
  
//Intrusion-Sets Shared Techniques > 2
MATCH (i1:intrusion_set)-[:USES]->(technique:attack_pattern)<-[:USES]-(i2:intrusion_set)
WHERE id(i1) < id(i2)
WITH i1, i2, collect(technique) as sharedTechniques
WHERE size(sharedTechniques) > 2
MATCH path = (i1)-[:USES]->(technique:attack_pattern)<-[:USES]-(i2)
WHERE technique IN sharedTechniques
RETURN path
  
===
  
//Report Refs Intrusion-Set and Malware
MATCH (n:report)-[:REFERENCES]->(m:malware)<-[:USES]-(i:intrusion_set)
MATCH (n:report)-[:REFERENCES]->(i:intrusion_set)
RETURN n, m, i 
LIMIT 100
  
===
  
//Shared Entities Between Reports
MATCH path = (r1:report)-[:REFERENCES]->(entity)<-[:REFERENCES]-(r2:report)
WHERE id(r1) < id(r2)  // Prevent duplicate relationships
WITH r1, r2, entity, path
RETURN path
LIMIT 100
  
===
  
//Show all node types
MATCH (n) RETURN DISTINCT labels(n)
  
===
  
//Show all relationship types
CALL db.relationshipTypes()


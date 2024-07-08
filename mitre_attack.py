from taxii2client.v20 import Server

def fetch_mitre_attack_data():
    server = Server("https://cti-taxii.mitre.org/taxii/")
    api_root = server.api_roots[0]
    collections = api_root.collections

    # For demonstration, let's use the Enterprise ATT&CK collection
    enterprise_attack_collection = collections[0]  # Ensure the correct index for your collection
    stix_data = enterprise_attack_collection.get_objects()
    
    return stix_data

def process_mitre_attack_data(stix_data, threat_model):
    processed_data = []
    
    for threat in threat_model:
        relevant_techniques = []
        keywords = threat.get('MITRE ATT&CK Keywords', [])
        
        if not keywords:
            processed_data.append({
                'threat': threat,
                'mitre_techniques': [],
            })
            continue
        
        for obj in stix_data['objects']:
            if obj['type'] == 'attack-pattern':
                name = obj.get('name', '').lower()
                description = obj.get('description', '').lower()
                for keyword in keywords:
                    keyword = keyword.lower()
                    if keyword in name or keyword in description:
                        relevant_techniques.append({
                            'name': obj['name'],
                            'description': obj.get('description', 'No description available'),
                            'id': obj['id']
                        })
                        break
        
        # Sort and take the top 2 most relevant techniques
        relevant_techniques = sorted(relevant_techniques, key=lambda x: len(x['description']))[:2]
        
        processed_data.append({
            'threat': threat,
            'mitre_techniques': relevant_techniques,
        })
    
    return processed_data

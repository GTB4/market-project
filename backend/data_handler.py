import json

def assemble_payload(packet_fragments, payload_count):
    full_payload = b''.join(packet_fragments[i] for i in sorted(packet_fragments))
    clean_data(full_payload, payload_count)

def clean_data(full_payload, payload_count):
    payload = full_payload
    clean_payload = {}

    for i in range(50):
        length = int.from_bytes(payload[0:2], byteorder='big')
        json_bytes = payload[2:length+2]
        payload = payload[length+2:]

        json_str = json_bytes.decode('utf-8')
        json_data = json.loads(json_str)

        clean_payload[i] = json_data
    
    # print(f"{clean_payload},\n {length}\n")
    list_payload = [clean_payload[i] for i in range(50)]
    push_data_to_api(list_payload)

def push_data_to_api(list_payload):
    print(f"list paylaod : {list_payload}")

if __name__ == "__main__":
    clean_data() 

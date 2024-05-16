import json

with open('vectors.json', 'r') as f:

    vectors = json.load(f) # deserialize using load()
    print(vectors) # print pickled data
    f.close

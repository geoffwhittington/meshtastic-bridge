import pickle

with open('vectors.pkl', 'rb') as f:

    vectors = pickle.load(f) # deserialize using load()
    print(vectors) # print pickled data
    f.close

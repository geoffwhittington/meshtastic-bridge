import pickle

balloon_lat = 180.00
balloon_lon = 90.00
balloon_alt = 1205.00
base_lat = 181.00
base_lon = 91.00
base_alt = 1215.00
distance = 100.00
bearing = 14.00
ant_elev = 19.00
file_path = 'vectors.pkl'

vectors = {
    'Antenna': {
        'Bearing': bearing, 'Elevation': ant_elev
        },

    'Base': {
        'Latitude': base_lat, 'Longitude': base_lon, 'Altitude': base_alt
        },
    'Balloon': {
        'Latitude': balloon_lat, 'Longitude': balloon_lon, 'Altitude': balloon_alt
        }
    }

# Open the file in binary mode
with open(file_path, 'wb') as f:
    # Serialize and write the variable to the file
    pickle.dump(vectors, f)
    f.close()

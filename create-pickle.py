import pickle

remote_lat = 180.00
remote_lon = 90.00
remote_alt = 1205.00
local_lat = 181.00
local_lon = 91.00
local_alt = 1215.00
distance = 100.00
bearing = 14.00
ant_elev = 19.00
file_path = 'vectors.pkl'

vectors = {
    'Antenna': {
        'Bearing': bearing, 'Elevation': ant_elev
        },

    'Local': {
        'Latitude': local_lat, 'Longitude': local_lon, 'Altitude': local_alt
        },
    'Remote': {
        'Latitude': remote_lat, 'Longitude': remote_lon, 'Altitude': remote_alt
        }
    }

# Open the file in binary mode
with open(file_path, 'wb') as f:
    # Serialize and write the variable to the file
    pickle.dump(vectors, f)
    f.close()

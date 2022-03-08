import os
import json

def get_API_JSON_files():
  """ Loads the API JSON documents. They are assumed to be in the API_JSON folder. """

  API_file_names = os.listdir('./API_JSON')
  API_JSON_files = []

  for API_file_name in API_file_names:
    with open('./API_JSON/'+API_file_name) as f:
      lines = f.readlines()
      joined_lines = ''
      for line in lines:
        joined_lines += line

      API_JSON_files.append(json.loads(joined_lines))

  return API_JSON_files
import os
import glob

def make_dir_if_does_not_exist(path):
    if not os.path.exists(path):
        os.makedirs(path)

def make_dir_from_file_path_if_does_not_exist(file_path):
    folder_path = os.path.dirname(file_path)
    make_dir_if_does_not_exist(folder_path)

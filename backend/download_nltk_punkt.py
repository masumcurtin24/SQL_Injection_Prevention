import nltk
import os
import sys

# Common NLTK data paths (NLTK searches these by default)
# The first one is often the user's home directory
default_paths = [
    os.path.join(os.path.expanduser("~"), "nltk_data"),
    r"C:\nltk_data", # Common global paths on Windows
    r"D:\nltk_data",
    r"E:\nltk_data",
    os.path.join(sys.prefix, "nltk_data"), # Inside Python/venv installation
    os.path.join(sys.prefix, "share", "nltk_data"),
    os.path.join(sys.prefix, "lib", "nltk_data"),
]

# Try to find an existing, writable nltk_data directory, or use the first default
download_dir = None
for path in default_paths:
    if os.path.exists(path) and os.access(path, os.W_OK):
        download_dir = path
        print(f"Found existing writable NLTK data directory: {download_dir}")
        break

if not download_dir:
    download_dir = default_paths[0] # Default to user's home nltk_data
    print(f"Defaulting NLTK download directory to: {download_dir}")
    if not os.path.exists(download_dir):
        try:
            os.makedirs(download_dir)
            print(f"Created directory: {download_dir}")
        except Exception as e:
            print(f"ERROR: Could not create NLTK data directory {download_dir}: {e}")
            print("Please manually create one of the NLTK data paths listed above and ensure it's writable.")
            exit()

print(f"\nAttempting to download 'punkt' to: {download_dir}")
print("If the NLTK Downloader GUI appears, please select 'punkt' and ensure the download path is set to the directory above.")
try:
    nltk.download('punkt', download_dir=download_dir)
    print("\nDownload command for 'punkt' executed.")
    print("Please check the console/GUI for success or error messages from the downloader.")

    # Verify if punkt_tab/english.pickle is now present
    punkt_english_pickle = os.path.join(download_dir, "tokenizers", "punkt", "PY3", "english.pickle")
    # Also check for the punkt_tab structure
    punkt_tab_english_dir = os.path.join(download_dir, "tokenizers", "punkt_tab", "english")

    if os.path.exists(punkt_english_pickle):
        print(f"SUCCESS: Found 'english.pickle' at {punkt_english_pickle}")
    else:
        print(f"WARNING: Did not find 'english.pickle' at {punkt_english_pickle} after download.")

    if os.path.exists(punkt_tab_english_dir) and os.listdir(punkt_tab_english_dir):
         print(f"SUCCESS: Found 'punkt_tab/english/' directory with content at {punkt_tab_english_dir}")
    else:
        print(f"WARNING: Did not find 'punkt_tab/english/' directory or it's empty at {punkt_tab_english_dir}")
        print("The 'punkt_tab' error might persist if this directory structure is missing.")

    print(f"\nNLTK will search for data in these paths (ensure '{download_dir}' is listed or add it manually in your notebook):")
    for path in nltk.data.path:
        print(f"- {path}")

except Exception as e:
    print(f"An error occurred during NLTK download: {e}")
    print("Try running `import nltk; nltk.download('all')` in a Python console.")
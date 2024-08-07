import requests
import hashlib
import os
import subprocess

def main():
    # Get the expected SHA-256 hash value of the VLC installer
    expected_sha256 = get_expected_sha256()

    # Download (but don't save) the VLC installer from the VLC website
    installer_data = download_installer()

    # Verify the integrity of the downloaded VLC installer by comparing the
    # expected and computed SHA-256 hash values
    if installer_ok(installer_data, expected_sha256):
        # Save the downloaded VLC installer to disk
        installer_path = save_installer(installer_data)

        # Silently run the VLC installer
        run_installer(installer_path)

        # Delete the VLC installer from disk
        delete_installer(installer_path)

def get_expected_sha256():
    """Downloads the text file containing the expected SHA-256 value for the VLC installer file from the 
    videolan.org website and extracts the expected SHA-256 value from it.

    Returns:
        str: Expected SHA-256 hash value of VLC installer
    """
    # TODO: Step 1
    url = 'https://get.videolan.org/vlc/last/win64/sha256sum.txt'
    response = requests.get(url)
    response.raise_for_status()  # Ensure we notice bad responses
    sha256_line = response.text.split()[0]  # Extract the SHA-256 hash from the first line
    return sha256_line

def download_installer():
    """Downloads, but does not save, the .exe VLC installer file for 64-bit Windows.

    Returns:
        bytes: VLC installer file binary data
    """
    # TODO: Step 2
    url = 'https://get.videolan.org/vlc/last/win64/vlc-3.0.11-win64.exe'
    response = requests.get(url)
    response.raise_for_status()  # Ensure we notice bad responses
    return response.content

def installer_ok(installer_data, expected_sha256):
    """Verifies the integrity of the downloaded VLC installer file by calculating its SHA-256 hash value 
    and comparing it against the expected SHA-256 hash value. 

    Args:
        installer_data (bytes): VLC installer file binary data
        expected_sha256 (str): Expected SHA-256 of the VLC installer

    Returns:
        bool: True if SHA-256 of VLC installer matches expected SHA-256. False if not.
    """    
    # TODO: Step 3
    sha256 = hashlib.sha256(installer_data).hexdigest()
    return sha256 == expected_sha256

def save_installer(installer_data):
    """Saves the VLC installer to a local directory.

    Args:
        installer_data (bytes): VLC installer file binary data

    Returns:
        str: Full path of the saved VLC installer file
    """
    # TODO: Step 4
    installer_path = 'vlc_installer.exe'
    with open(installer_path, 'wb') as file:
        file.write(installer_data)
    return installer_path

def run_installer(installer_path):
    """Silently runs the VLC installer.

    Args:
        installer_path (str): Full path of the VLC installer file
    """    
    # TODO: Step 5
    subprocess.run([installer_path, '/S'], check=True)  # '/S' for silent installation

def delete_installer(installer_path):
    """Deletes the VLC installer file.

    Args:
        installer_path (str): Full path of the VLC installer file
    """
    # TODO: Step 6
    os.remove(installer_path)

if __name__ == '__main__':
    main()

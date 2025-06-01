# =============================================================================
# VeraCrypt Launchpad Uploader
# =============================================================================
#
# Author: Mounir IDRASSI <mounir.idrassi@amcrypto.jp>
# Date: May 31st, 2025
# 
# This script is part of the VeraCrypt project
# https://www.veracrypt.jp
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Description:
# This script automates the process of uploading VeraCrypt release packages
# to Launchpad. It authenticates with Launchpad, locates the appropriate
# project, series, milestone, and release, and then uploads all package files
# from a specified directory, skipping any that have already been uploaded.
# =============================================================================

import os
import mimetypes
from launchpadlib.launchpad import Launchpad

# === CONFIGURATION ===
PROJECT_NAME    = 'veracrypt'
SERIES_NAME     = 'trunk'
MILESTONE_NAME  = '1.26.24'
RELEASE_VERSION = '1.26.24'
FILES_DIRECTORY = r"/opt/VeraCrypt_Packages/1.26.24"

APPLICATION_NAME = 'launchpad-batch-uploader'
CACHEDIR         = os.path.expanduser(r"~/.launchpadlib/cache")

# === AUTHENTICATION ===
print("Authenticating with Launchpad…")
launchpad = Launchpad.login_with(APPLICATION_NAME, 'production', CACHEDIR)

# === LOOK UP TARGET OBJECTS ===
try:
    # First try direct dictionary-style lookup
    project = launchpad.projects[PROJECT_NAME]
except KeyError:
    # Fallback: use getByName on projects
    project = launchpad.projects.getByName(name=PROJECT_NAME)
    if project is None:
        raise Exception(f"Project '{PROJECT_NAME}' not found.")

# Safely fetch the series object
try:
    series = project.series[SERIES_NAME]
except (KeyError, TypeError):
    series = project.getSeries(name=SERIES_NAME)
    if series is None:
        raise Exception(f"Series '{SERIES_NAME}' not found in project '{PROJECT_NAME}'.")

# === REPLACE getMilestone with a loop over all_milestones ===
milestone = None
print(f"Locating milestone '{MILESTONE_NAME}' in series '{SERIES_NAME}'…")
for m in series.all_milestones:  # ← series.all_milestones is a PagedCollection of Milestone
    if m.name == MILESTONE_NAME:
        milestone = m
        break

if milestone is None:
    raise Exception(f"Milestone '{MILESTONE_NAME}' not found in series '{SERIES_NAME}'.")

# --- FIND THE RELEASE UNDER THAT MILESTONE ----------------------------
print(f"Locating release for milestone '{MILESTONE_NAME}'…")

try:
    release = milestone.release              # <-- the only release tied to this milestone
except AttributeError:
    # (very old Launchpadlib versions expose only the _link)
    release = launchpad.load(milestone.release_link)

# sanity-check
if release is None or release.version != RELEASE_VERSION:
    raise Exception(
        f"Expected version '{RELEASE_VERSION}', "
        f"but milestone only links to '{getattr(release, 'version', None)}'."
    )
print("Release found. Beginning upload…")

# === UPLOAD FILES ===

# Build a set of filenames already present on the release
existing_files = set()
for f in release.files:
    # Each f is a URL; the filename is after the last '/'
    filename_on_release = os.path.basename(f.self_link)
    existing_files.add(filename_on_release)

# Print existing files if existing_files is not empty
if not existing_files:
    print("No files already uploaded to this release.")
else:
    print("Files already uploaded to this release:")
    for ef in sorted(existing_files):
        print(" -", ef)

print()

for filename in os.listdir(FILES_DIRECTORY):
    if filename.endswith('.sig'):
        continue

    if filename in existing_files:
        print(f">>> Skipping {filename} (already uploaded)")
        continue

    filepath = os.path.join(FILES_DIRECTORY, filename)
    sig_path = filepath + '.sig'
    has_signature = os.path.isfile(sig_path)

    content_type, _ = mimetypes.guess_type(filepath)
    content_type = content_type or 'application/octet-stream'

    print(f"Uploading: {filename} (type: {content_type})")
    try:
        with open(filepath, 'rb') as file_content:
            file_bytes = file_content.read()
            if has_signature:
                with open(sig_path, 'rb') as sig_handle:
                    sig_bytes = sig_handle.read()
                    release.add_file(
                        description=f"Uploaded file: {filename}",
                        content_type=content_type,
                        filename=filename,
                        file_content=file_bytes,
                        signature_filename=os.path.basename(sig_path),
                        signature_content=sig_bytes
                    )
                print(f" -> Uploaded {filename} with signature.")
            else:
                release.add_file(
                    description=f"Uploaded file: {filename}",
                    content_type=content_type,
                    filename=filename,
                    file_content=file_bytes,
                    signature_filename=None,
                    signature_content=None
                )
                print(f" -> Uploaded {filename} without signature.")
    except Exception as e:
        print(f"!!!  Failed to upload '{filename}': {e}")
        continue

print("Done! All files uploaded (or attempted) successfully.")

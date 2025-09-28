#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Aug 26 00:34:46 2025

@author: blackangel
"""

# ##############################################################################
# ## Key Triangulator - A Research Tool for Cryptographic Analysis
# ##############################################################################
# ## WARNING: FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.
# ##############################################################################

import subprocess
import re
import base58
import hashlib
import ecdsa
import time
import os

# --- CONFIGURATION ---
VANITY_SEARCH_EXECUTABLE = "/home/blackangel/vanitygen-plusplus-master/oclvanitygen++"
TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
SEARCH_PREFIX = "1PWo3Je"
CANDIDATE_COUNT = 10  # Reduced for testing
WORKING_DIR = "/home/blackangel/vanitygen-plusplus-master/"

# Key range configuration - ADDED THIS SECTION
USE_KEY_RANGE = True  # Set to False to disable key range search
START_KEY = "0000000000000000000000000000000000000000000000690B84B6431A88856B"  # Start of range in hex
END_KEY = "0000000000000000000000000000000000000000000000795B84B6431A88856B"  # End of range in hex
RANGE_LENGTH = (((256-71)))  #None  # Alternatively, specify range length (e.g., $((256-71)))

def wif_to_hex(wif):
    """Convert WIF private key to hexadecimal format."""
    try:
        # Base58 decode
        decoded = base58.b58decode(wif)

        # Remove network byte and checksum
        if len(decoded) == 37:  # Uncompressed WIF
            private_key = decoded[1:33]
        elif len(decoded) == 38:  # Compressed WIF
            private_key = decoded[1:33]
        else:
            return None

        return private_key.hex()
    except Exception as e:
        print(f"[!] Error converting WIF to hex: {e}")
        return None

def run_vanity_search(prefix, count):
    """
    Runs the external vanity search tool to generate candidate keys.
    Uses a different approach to capture output.
    """
    print(f"[*] Starting vanity search for {count} candidates with prefix '{prefix}'...")

    # Build command with key range options - MODIFIED THIS SECTION
    command = [VANITY_SEARCH_EXECUTABLE,"-p", "1", "-d", "0", "-v", "-k"]

    # Add key range options if enabled
    if USE_KEY_RANGE:
        if RANGE_LENGTH is not None:
            command.extend(["-Z", START_KEY, "-l", str(RANGE_LENGTH)])
        else:
            # If no range length specified, use start and end keys
            command.extend(["-Z", START_KEY])
            # Note: vanitygen++ doesn't directly support end key,
            # so we'll need to stop manually when we reach it

    command.append(prefix)

    try:
        # Run the process and capture output
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=WORKING_DIR,
            bufsize=1  # Line buffered
        )

        output = ""
        candidates_found = 0

        # Read output line by line
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break

            output += line
            print(line, end='')  # Show progress

            # Check if we found a candidate
            if "Address:" in line and "Privkey:" in output:
                candidates_found += 1
                print(f"[*] Found candidate {candidates_found}/{count}")

            # Stop if we have enough candidates
            if candidates_found >= count:
                process.terminate()
                break

            # Additional check for key range - ADDED THIS SECTION
            if USE_KEY_RANGE and RANGE_LENGTH is None:
                # Extract private key from output and check if we've reached the end key
                privkey_match = re.search(r"Privkey \(hex\):\s+([0-9A-Fa-f]{64})", line)
                if privkey_match:
                    current_key = privkey_match.group(1)
                    if int(current_key, 16) >= int(END_KEY, 16):
                        print(f"[*] Reached end of key range: {END_KEY}")
                        process.terminate()
                        break

        # Get any remaining output
        stdout, stderr = process.communicate()
        output += stdout

        if stderr:
            print(f"[!] Errors: {stderr}")

        return output

    except FileNotFoundError:
        print(f"[!] ERROR: vanitygen++ executable not found at '{VANITY_SEARCH_EXECUTABLE}'")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        return None

def parse_vanity_output(output):
    """
    Parses the text output from the vanity search tool to extract
    private keys and addresses.
    """
    candidates = []

    # Regex pattern to match vanitygen++ output
    pattern = re.compile(
        r"Address:\s+([13][a-km-zA-HJ-NP-Z1-9]{25,34})\s*" +
        r"Privkey:\s+([KL5][1-9A-HJ-NP-Za-km-z]{50,51})",
        re.MULTILINE
    )

    matches = pattern.findall(output)
    print(f"[*] Found {len(matches)} pattern matches in output")

    for address, priv_key_wif in matches:
        # Only process addresses with our desired prefix
        if address.startswith(SEARCH_PREFIX):
            priv_key_hex = wif_to_hex(priv_key_wif)
            if priv_key_hex:
                candidates.append({
                    "priv_key": priv_key_hex,
                    "address": address,
                    "priv_key_wif": priv_key_wif
                })
                print(f"[+] Valid candidate: {address}")
            else:
                print(f"[!] Failed to convert WIF for address: {address}")

    print(f"[*] Successfully parsed {len(candidates)} candidates with prefix '{SEARCH_PREFIX}'")
    return candidates

def address_to_decimal_hash160(address):
    """
    Decodes a Base58 address and returns the decimal integer value of its hash160.
    """
    try:
        decoded_bytes = base58.b58decode(address)
        # The hash160 is bytes 1 through 20 (20 bytes total)
        hash160_bytes = decoded_bytes[1:21]
        return int.from_bytes(hash160_bytes, 'big')
    except Exception as e:
        print(f"[!] Error decoding address {address}: {e}")
        return None

def main():
    """
    Main function to run the triangulation process.
    """
    print("--- Starting Key Triangulation Analysis ---")

    # Display key range info if enabled - ADDED THIS SECTION
    if USE_KEY_RANGE:
        print(f"[*] Using key range: {START_KEY} to {END_KEY}")
        if RANGE_LENGTH is not None:
            print(f"[*] Range length: {RANGE_LENGTH}")

    # 1. Generate candidate keys
    vanity_output = run_vanity_search(SEARCH_PREFIX, CANDIDATE_COUNT)
    if not vanity_output:
        print("[!] No output from vanitygen++. Exiting.")
        return

    # Save output for debugging
    with open("vanity_output.txt", "w") as f:
        f.write(vanity_output)
    print("[*] Saved raw output to vanity_output.txt")

    candidates = parse_vanity_output(vanity_output)
    if not candidates:
        print("[!] No candidates found. Check vanity_output.txt for details.")
        return

    # 2. Convert target address to its decimal representation
    target_decimal = address_to_decimal_hash160(TARGET_ADDRESS)
    if target_decimal is None:
        print(f"[!] Invalid target address: {TARGET_ADDRESS}")
        return

    print(f"\n[TARGET] Address: {TARGET_ADDRESS}")
    print(f"[TARGET] Decimal Hash160: {target_decimal}")

    # 3. Find the upper and lower bounds
    lower_bound = {"decimal_diff": float('inf'), "data": None}
    upper_bound = {"decimal_diff": float('inf'), "data": None}

    for cand in candidates:
        cand_decimal = address_to_decimal_hash160(cand["address"])
        if cand_decimal is None:
            continue

        diff = target_decimal - cand_decimal

        # Find the best lower bound
        if diff > 0 and diff < lower_bound["decimal_diff"]:
            lower_bound["decimal_diff"] = diff
            lower_bound["data"] = cand
            lower_bound["data"]["decimal"] = cand_decimal

        # Find the best upper bound
        if diff < 0 and abs(diff) < upper_bound["decimal_diff"]:
            upper_bound["decimal_diff"] = abs(diff)
            upper_bound["data"] = cand
            upper_bound["data"]["decimal"] = cand_decimal

    # 4. Print the results
    print("\n--- Triangulation Results ---")

    if lower_bound["data"]:
        lb_data = lower_bound['data']
        print(f"\n[LOWER BOUND] Address: {lb_data['address']}")
        print(f"[LOWER BOUND] Decimal: {lb_data['decimal']}")
        print(f"[LOWER BOUND] PrivKey: 0x{lb_data['priv_key']}")
    else:
        print("\n[!] No suitable lower bound found in candidates.")

    print(f"\n<<<<<<<<<< [ TARGET IS HERE ] >>>>>>>>>>\n")

    if upper_bound["data"]:
        ub_data = upper_bound['data']
        print(f"[UPPER BOUND] Address: {ub_data['address']}")
        print(f"[UPPER BOUND] Decimal: {ub_data['decimal']}")
        print(f"[UPPER BOUND] PrivKey: 0x{ub_data['priv_key']}")
    else:
        print("[!] No suitable upper bound found in candidates.")

    # 5. Define the final, narrow search range
    if lower_bound["data"] and upper_bound["data"]:
        start_key = lower_bound['data']['priv_key']
        end_key = upper_bound['data']['priv_key']

        # Ensure start_key is smaller than end_key
        if int(start_key, 16) > int(end_key, 16):
            start_key, end_key = end_key, start_key

        print("\n--- Next Steps ---")
        print("The target private key is likely located between the Lower and Upper bound keys.")
        print("The next step is to perform a high-speed, sequential search within this narrow range.")
        print(f"\nRECOMMENDED SEARCH RANGE:")
        print(f"Start Key: 0x{start_key}")
        print(f"End Key:   0x{end_key}")

        # Generate command for next search - ADDED THIS SECTION
        print(f"\nTo continue the search with this range, use:")
        print(f"{VANITY_SEARCH_EXECUTABLE} -v -k -Z {start_key} -l {hex(int(end_key, 16) - int(start_key, 16))} {SEARCH_PREFIX}")
    else:
        print("\n[!] Could not establish a valid search range.")

if __name__ == "__main__":
    main()

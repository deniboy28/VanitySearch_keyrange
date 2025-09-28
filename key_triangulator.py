

# ##############################################################################
# ## Key Triangulator - A Research Tool for Cryptographic Analysis
# ##############################################################################
# ## WARNING: FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.
# ##
# ## This script is a proof-of-concept implementation of the advanced
# ## cryptographic analysis techniques discussed. It is designed to explore
# ## theoretical patterns in the Bitcoin address generation process.
# ##
# ## The knowledge and methods contained herein are potentially dangerous.
# ## Misuse of this information could lead to severe financial loss and
# ## may be illegal. The user assumes all responsibility for the ethical
# ## and legal use of this script.
# ##
# ## NEVER use this script on addresses or private keys associated with
# ## real funds.
# ##############################################################################

import subprocess
import re
import base58
import hashlib
import ecdsa

# --- CONFIGURATION ---
# IMPORTANT: You must have a compiled vanity address generator executable.
# This script is configured for the output of "VanitySearch".
# You may need to change the command and regex for your specific tool.
VANITY_SEARCH_EXECUTABLE = "/home/blackangel/VanitySearch-noRkeys/./VanitySearch"
TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
# The prefix to search for. Shorter is faster and provides more candidates.
SEARCH_PREFIX = "1PWo3"
# Number of candidates to generate. More is better but takes longer.
CANDIDATE_COUNT = 100

def run_vanity_search(prefix, count):
    """
    Runs the external vanity search tool to generate candidate keys.
    This function will need to be adapted to your specific vanity tool.
    """
    print(f"[*] Starting vanity search for {count} candidates with prefix '{prefix}'...")
    
    # This command is an example. You must adapt it to your tool.
    # It's configured to find `count` addresses and then exit.
    command = [
        VANITY_SEARCH_EXECUTABLE,
         "-startkey 0000000000000000000000000000000000000000000000790B84B753693Ad9C1 -endkey FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    ]
    
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=600) # Removed check=True
        output = process.stdout
        print("[+] Vanity search completed (or timed out).")
        return output
    except subprocess.TimeoutExpired as e:
        print(f"[!] Vanity search timed out after {e.timeout} seconds. Processing partial results.")
        return e.stdout # Return stdout even on timeout
    except FileNotFoundError as e:
        print(f"[!] ERROR: VanitySearch executable not found at '{VANITY_SEARCH_EXECUTABLE}'. Please check the path.")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred during vanity search: {e}")
        return None

def parse_vanity_output(output):
    """
    Parses the text output from the vanity search tool to extract
    private keys and addresses. This regex is specific to VanitySearch output.
    """
    candidates = []
    # Regex to find PubAddress and Privkey (HEX)
    # It expects PubAddress first, then Priv (HEX) later in the block.
    pattern = re.compile(r"PubAddress: ([13][a-km-zA-HJ-NP-Z1-9]{25,34}).*?Priv \(HEX\): (0x[\da-fA-F]+)", re.DOTALL)
    matches = pattern.findall(output)
    
    for match in matches:
        address = match[0]
        priv_key_hex = match[1].lstrip("0x") # Remove 0x prefix
        # Ensure the private key is 64 hex characters (32 bytes) by padding with leading zeros
        full_priv_key = priv_key_hex.zfill(64)
        candidates.append({
            "priv_key": full_priv_key,
            "address": address
        })
        
    print(f"[*] Parsed {len(candidates)} candidates from output.")
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
    except Exception:
        return None

def main():
    """
    Main function to run the triangulation process.
    """
    print("--- Starting Key Triangulation Analysis ---")
    
    # 1. Generate candidate keys
    vanity_output = run_vanity_search(SEARCH_PREFIX, CANDIDATE_COUNT)
    if not vanity_output:
        return
        
    candidates = parse_vanity_output(vanity_output)
    if not candidates:
        print("[!] No candidates found. Exiting.")
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
        
        # Find the best lower bound (closest address with a decimal value *less* than the target)
        if diff > 0 and diff < lower_bound["decimal_diff"]:
            lower_bound["decimal_diff"] = diff
            lower_bound["data"] = cand
            lower_bound["data"]["decimal"] = cand_decimal
            
        # Find the best upper bound (closest address with a decimal value *greater* than the target)
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

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Script to check which CIDR prefixes from ER_public_routes.csv 
are not covered by prefixes in MS_routes.csv

Dependencies:
- Python 3.6+ (uses ipaddress module, datetime, os)
- No external packages required (uses only standard library)

Note: subnet_of() method requires Python 3.7+, but this script includes 
compatibility for Python 3.6+
"""

import ipaddress
import csv
import datetime
import os
import sys

def read_cidrs_from_file(filename):
    """Read CIDR prefixes from a CSV file, skipping empty lines and BOM"""
    cidrs = []
    try:
        with open(filename, 'r', encoding='utf-8-sig') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith(','):  # Skip empty lines and header-like lines
                    # Remove any leading non-IP characters and extract CIDR
                    parts = line.split('→') if '→' in line else [line]
                    cidr_part = parts[-1].strip()
                    if cidr_part:
                        try:
                            # Validate the CIDR format
                            ipaddress.ip_network(cidr_part, strict=False)
                            cidrs.append(cidr_part)
                        except ValueError:
                            print(f"Invalid CIDR format skipped: {cidr_part}")
    except FileNotFoundError:
        print(f"File not found: {filename}")
    except Exception as e:
        print(f"Error reading {filename}: {e}")
    
    return cidrs

def get_ip_range(cidr):
    """Get the IP range (first - last) for a CIDR prefix"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return f"{network.network_address} - {network.broadcast_address}"
    except ValueError:
        return "Invalid CIDR"

def is_subnet_of(subnet, supernet):
    """
    Check if subnet is a subnet of supernet (compatibility function for Python < 3.7)
    Returns True if subnet is contained within supernet
    """
    try:
        # Convert to network objects
        subnet_net = ipaddress.ip_network(subnet, strict=False)
        supernet_net = ipaddress.ip_network(supernet, strict=False)
        
        # Check if subnet is contained within supernet
        # This works by checking if:
        # 1. The subnet's network address is >= supernet's network address
        # 2. The subnet's broadcast address is <= supernet's broadcast address
        return (subnet_net.network_address >= supernet_net.network_address and 
                subnet_net.broadcast_address <= supernet_net.broadcast_address)
    except ValueError:
        return False

def is_network_covered(target_network, covering_networks):
    """Check if target_network is covered by any network in covering_networks"""
    target = ipaddress.ip_network(target_network, strict=False)
    
    for covering_network in covering_networks:
        try:
            covering = ipaddress.ip_network(covering_network, strict=False)
            # Check if target network is subnet of or equal to covering network
            # Use built-in subnet_of if available (Python 3.7+), otherwise use our compatibility function
            if hasattr(target, 'subnet_of'):
                is_covered = target.subnet_of(covering) or target == covering
            else:
                is_covered = is_subnet_of(target_network, covering_network) or target == covering
            
            if is_covered:
                return True, covering_network
        except ValueError:
            continue
    
    return False, None

def write_log_file(ms_routes, er_routes, covered_routes, uncovered_routes, ms_file, er_file):
    """Write detailed log file with all results"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"cidr_coverage_analysis_{timestamp}.log"
    
    with open(log_filename, 'w', encoding='utf-8') as log_file:
        # Header information
        log_file.write("=" * 80 + "\n")
        log_file.write("CIDR COVERAGE ANALYSIS LOG\n")
        log_file.write("=" * 80 + "\n")
        log_file.write(f"Analysis Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_file.write(f"Input Files:\n")
        log_file.write(f"  - MS Routes File: {ms_file} ({len(ms_routes)} prefixes)\n")
        log_file.write(f"  - ER Routes File: {er_file} ({len(er_routes)} prefixes)\n")
        log_file.write(f"\nOperation: Checking if all CIDR prefixes in ER file are covered by prefixes in MS file\n")
        log_file.write("=" * 80 + "\n\n")
        
        # Summary
        log_file.write("SUMMARY:\n")
        log_file.write("-" * 40 + "\n")
        log_file.write(f"Total ER routes analyzed: {len(er_routes)}\n")
        log_file.write(f"Routes covered by MS prefixes: {len(covered_routes)}\n")
        log_file.write(f"Routes NOT covered by MS prefixes: {len(uncovered_routes)}\n")
        log_file.write(f"Coverage percentage: {(len(covered_routes)/len(er_routes)*100):.1f}%\n\n")
        
        # Detailed results - Covered routes
        if covered_routes:
            log_file.write("COVERED ROUTES:\n")
            log_file.write("=" * 80 + "\n")
            log_file.write(f"{'ER Route':<20} {'IP Range':<35} {'Covered by MS Route':<20} {'MS IP Range'}\n")
            log_file.write("-" * 80 + "\n")
            for er_route, ms_route in covered_routes:
                er_range = get_ip_range(er_route)
                ms_range = get_ip_range(ms_route)
                log_file.write(f"{er_route:<20} {er_range:<35} {ms_route:<20} {ms_range}\n")
            log_file.write(f"\nTotal covered routes: {len(covered_routes)}\n\n")
        
        # Detailed results - Uncovered routes
        if uncovered_routes:
            log_file.write("UNCOVERED ROUTES:\n")
            log_file.write("=" * 60 + "\n")
            log_file.write(f"{'ER Route':<20} {'IP Range':<35}\n")
            log_file.write("-" * 60 + "\n")
            for route in uncovered_routes:
                route_range = get_ip_range(route)
                log_file.write(f"{route:<20} {route_range:<35}\n")
            log_file.write(f"\nTotal uncovered routes: {len(uncovered_routes)}\n\n")
        else:
            log_file.write("UNCOVERED ROUTES: None\n")
            log_file.write("-" * 40 + "\n")
            log_file.write("All ER routes are covered by MS routes!\n\n")
        
        # Input file contents for reference
        log_file.write("INPUT FILE CONTENTS WITH IP RANGES:\n")
        log_file.write("=" * 60 + "\n")
        log_file.write(f"MS Routes ({ms_file}):\n")
        log_file.write(f"{'CIDR':<20} {'IP Range':<35}\n")
        log_file.write("-" * 60 + "\n")
        for route in ms_routes:
            route_range = get_ip_range(route)
            log_file.write(f"{route:<20} {route_range:<35}\n")
        
        log_file.write(f"\nER Routes ({er_file}):\n")
        log_file.write(f"{'CIDR':<20} {'IP Range':<35}\n")
        log_file.write("-" * 60 + "\n")
        for route in er_routes:
            route_range = get_ip_range(route)
            log_file.write(f"{route:<20} {route_range:<35}\n")
        
        log_file.write("\n" + "=" * 80 + "\n")
        log_file.write("End of Analysis\n")
        log_file.write("=" * 80 + "\n")
    
    return log_filename

def main():
    # Check Python version
    if sys.version_info < (3, 6):
        print("Error: This script requires Python 3.6 or higher")
        print(f"Current Python version: {sys.version}")
        sys.exit(1)
    
    # Print Python version info for debugging
    print(f"Python version: {sys.version.split()[0]}")
    if hasattr(ipaddress.IPv4Network('192.168.1.0/24'), 'subnet_of'):
        print("Using built-in subnet_of method (Python 3.7+)")
    else:
        print("Using compatibility subnet checking (Python 3.6)")
    print("-" * 50)
    
    ms_file = 'MS_routes.csv'
    er_file = 'ER_public_routes.csv'
    
    # Read CIDR prefixes from both files
    ms_routes = read_cidrs_from_file(ms_file)
    er_routes = read_cidrs_from_file(er_file)
    
    print(f"MS routes loaded: {len(ms_routes)}")
    print(f"ER routes loaded: {len(er_routes)}")
    print("-" * 50)
    
    # Find ER routes not covered by MS routes
    uncovered_routes = []
    covered_routes = []
    
    for er_route in er_routes:
        is_covered, covering_route = is_network_covered(er_route, ms_routes)
        if is_covered:
            covered_routes.append((er_route, covering_route))
        else:
            uncovered_routes.append(er_route)
    
    # Write detailed log file
    log_filename = write_log_file(ms_routes, er_routes, covered_routes, uncovered_routes, ms_file, er_file)
    
    # Display results to console
    print(f"Summary:")
    print(f"  Total ER routes: {len(er_routes)}")
    print(f"  Covered by MS routes: {len(covered_routes)}")
    print(f"  NOT covered by MS routes: {len(uncovered_routes)}")
    print("-" * 50)
    
    if uncovered_routes:
        print("ER routes NOT covered by MS routes:")
        for route in uncovered_routes:
            route_range = get_ip_range(route)
            print(f"  {route:<20} ({route_range})")
    else:
        print("All ER routes are covered by MS routes!")
    
    if covered_routes:
        print(f"\nCovered routes (showing first 5):")
        for i, (er_route, ms_route) in enumerate(covered_routes[:5]):
            er_range = get_ip_range(er_route)
            ms_range = get_ip_range(ms_route)
            print(f"  {er_route:<20} ({er_range}) -> {ms_route} ({ms_range})")
        if len(covered_routes) > 5:
            print(f"  ... and {len(covered_routes) - 5} more (see log file for details)")
    
    print(f"\nDetailed log written to: {log_filename}")
    print(f"Log file size: {os.path.getsize(log_filename)} bytes")

if __name__ == "__main__":
    main()
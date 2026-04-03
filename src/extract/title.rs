use regex::Regex;

/// Extract the <title> from HTML body. Fast regex, no full DOM parse.
pub fn extract_title(body: &str) -> String {
    // Try regex first — fastest path for well-formed HTML
    let re = Regex::new(r"(?is)<title[^>]*>\s*(.*?)\s*</title>").unwrap();
    if let Some(cap) = re.captures(body) {
        if let Some(m) = cap.get(1) {
            let title = m.as_str().trim();
            // Decode basic HTML entities
            let title = title
                .replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#39;", "'")
                .replace("&apos;", "'");
            // Collapse whitespace
            let title: String = title.split_whitespace().collect::<Vec<_>>().join(" ");
            if !title.is_empty() {
                return title;
            }
        }
    }
    String::new()
}

package main

import (
    "bufio"
    "crypto/tls"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
    "time"
)

type ScanResult struct {
    URL           string
    Domain        string
    RedirectChain []string
    Vulnerabilities []Vulnerability
}

type Vulnerability struct {
    Type        string
    Severity    string
    Description string
    Evidence    string
}

var (
    client *http.Client
    wg     sync.WaitGroup
    mu     sync.Mutex
    results []ScanResult
)

// Common takeover services patterns

var takeoverServices = map[string][]string{
    // Cloud Services
    "aws": {
        "s3.amazonaws.com",
        "cloudfront.net",
        "amazonaws.com",
        "awsglobalaccelerator.com",
        "elb.amazonaws.com",
        "awsapprunner.com",
        "amplifyapp.com",
        "execute-api.us-east-1.amazonaws.com",
        "amazoncognito.com",
    },
    
    // Microsoft Azure
    "azure": {
        "azurewebsites.net",
        "cloudapp.net",
        "azure-api.net",
        "azurecontainer.io",
        "azurehdinsight.net",
        "azureedge.net",
        "azurestaticapps.net",
        "azuredatalakestore.net",
        "azurehdinsight.net",
        "trafficmanager.net",
        "blob.core.windows.net",
        "azurecr.io",
    },
    
    // Google Cloud
    "google": {
        "appspot.com",
        "cloudfunctions.net",
        "run.app",
        "web.app",
        "firebaseapp.com",
        "cloud.goog",
        "pages.dev",
        "workers.dev",
    },
    
    // Firebase
    "firebase": {
        "firebaseapp.com",
        "web.app",
        "firebaseio.com",
        "firebase.google.com",
    },
    
    // GitHub
    "github": {
        "github.io",
        "githubusercontent.com",
        "github.com",
        "github.dev",
        "githubapp.com",
        "githubassets.com",
    },
    
    // GitLab
    "gitlab": {
        "gitlab.io",
        "gitlab-static.net",
        "gitlab.net",
    },
    
    // Heroku
    "heroku": {
        "herokuapp.com",
        "herokudns.com",
        "herokussl.com",
        "herokuapp.net",
    },
    
    // Fastly
    "fastly": {
        "fastly.net",
        "fastlylb.net",
        "fastly-terrarium.com",
    },
    
    // Shopify
    "shopify": {
        "myshopify.com",
        "shopify.com",
        "shopifycdn.com",
        "shopifyapps.com",
        "shopifysvc.com",
    },
    
    // Squarespace
    "squarespace": {
        "squarespace.com",
        "sqspcdn.com",
        "square.site",
    },
    
    // WordPress
    "wordpress": {
        "wordpress.com",
        "wpengine.com",
        "wpenginepowered.com",
        "wpshower.com",
        "wp.com",
        "a8c.net",
        "automattic.com",
    },
    
    // Wix
    "wix": {
        "wixsite.com",
        "wix.com",
        "editorx.com",
        "wixstudio.com",
    },
    
    // Netlify
    "netlify": {
        "netlify.app",
        "netlify.com",
        "netlifyglobalcdn.com",
    },
    
    // Vercel (Zeit)
    "vercel": {
        "vercel.app",
        "now.sh",
        "zeit.co",
        "nowcdn.io",
    },
    
    // Cloudflare
    "cloudflare": {
        "workers.dev",
        "pages.dev",
        "r2.dev",
        "cloudflarestream.com",
        "cloudflareaccess.com",
    },
    
    // Bitbucket
    "bitbucket": {
        "bitbucket.io",
        "bitbucket.org",
    },
    
    // Pantheon
    "pantheon": {
        "pantheonsite.io",
        "pantheon.io",
        "getpantheon.com",
    },
    
    // Akamai
    "akamai": {
        "akamaiedge.net",
        "akamai.net",
        "akamaitechnologies.com",
        "akamaitechnologies.fr",
        "edgesuite.net",
        "edgekey.net",
    },
    
    // DigitalOcean
    "digitalocean": {
        "ondigitalocean.app",
        "digitaloceanspaces.com",
        "nyc3.digitaloceanspaces.com",
        "sgp1.digitaloceanspaces.com",
    },
    
    // IBM Cloud
    "ibm": {
        "cloud.ibm.com",
        "mybluemix.net",
        "eu-gb.mybluemix.net",
        "us-south.mybluemix.net",
    },
    
    // Oracle Cloud
    "oracle": {
        "oraclecloud.com",
        "oraclecloudapps.com",
        "oraclegovcloud.com",
    },
    
    // Linode
    "linode": {
        "linodeobjects.com",
        "linodeusercontent.com",
    },
    
    // Acquia
    "acquia": {
        "acquia-test.co",
        "acquia-sites.com",
        "acsitefactory.com",
    },
    
    // Zendesk
    "zendesk": {
        "zendesk.com",
        "zendesk.co",
        "zdassets.com",
    },
    
    // Unbounce
    "unbounce": {
        "unbouncepages.com",
        "unbounce.com",
    },
    
    // Tumblr
    "tumblr": {
        "tumblr.com",
        "tumblr.co",
    },
    
    // JsDelivr
    "jsdelivr": {
        "jsdelivr.net",
        "cdn.jsdelivr.net",
    },
    
    // LaunchRock
    "launchrock": {
        "launchrock.com",
        "launchrock.co",
    },
    
    // Statuspage
    "statuspage": {
        "statuspage.io",
        "status.io",
    },
    
    // Readme.io
    "readme": {
        "readme.io",
        "readme.com",
    },
    
    // SurveyMonkey
    "surveymonkey": {
        "surveymonkey.com",
        "surveymonkey.co",
    },
    
    // Typeform
    "typeform": {
        "typeform.com",
        "typeform.to",
    },
    
    // Instapage
    "instapage": {
        "instapage.com",
        "instapage.us",
    },
    
    // Intercom
    "intercom": {
        "intercom.help",
        "intercom.io",
        "intercomassets.com",
    },
    
    // Help Scout
    "helpscout": {
        "helpscoutdocs.com",
        "helpscout.com",
    },
    
    // Cargo Collective
    "cargo": {
        "cargocollective.com",
        "cargo.site",
    },
    
    // Kajabi
    "kajabi": {
        "kajabi.com",
        "kajabiusercontent.com",
    },
    
    // Thinkific
    "thinkific": {
        "thinkific.com",
        "thinkificusercontent.com",
    },
    
    // Teachable
    "teachable": {
        "teachable.com",
        "teachablecdn.com",
    },
    
    // Podia
    "podia": {
        "podia.com",
        "podiadns.com",
    },
    
    // Webflow
    "webflow": {
        "webflow.io",
        "webflow.com",
        "proxy.webflow.com",
    },
    
    // Carrd
    "carrd": {
        "carrd.co",
        "carrd.us",
    },
    
    // Strikingly
    "strikingly": {
        "strikingly.com",
        "strikinglydns.com",
    },
    
    // UptimeRobot
    "uptimerobot": {
        "uptimerobot.com",
        "statuspage.io",
    },
    
    // Pingdom
    "pingdom": {
        "pingdom.com",
        "pingdom.net",
    },
    
    // Freshdesk
    "freshdesk": {
        "freshdesk.com",
        "freshservice.com",
    },
    
    // Helpjuice
    "helpjuice": {
        "helpjuice.com",
        "helpjuice.io",
    },
    
    // Zoho
    "zoho": {
        "zoho.com",
        "zohocorp.com",
        "zohopublic.com",
    },
    
    // Mailchimp
    "mailchimp": {
        "mailchimp.com",
        "mailchimpcdn.com",
    },
    
    // Campaign Monitor
    "campaignmonitor": {
        "createsend.com",
        "campaignmonitor.com",
    },
    
    // HubSpot
    "hubspot": {
        "hubspot.com",
        "hubspotusercontent.com",
        "hs-sites.com",
        "hs-apps.com",
    },
    
    // Ghost
    "ghost": {
        "ghost.io",
        "ghost.org",
    },
    
    // Medium
    "medium": {
        "medium.com",
        "cdn.medium.com",
    },
    
    // Blogger
    "blogger": {
        "blogspot.com",
        "blogger.com",
    },
    
    // Notion
    "notion": {
        "notion.site",
        "notion.so",
    },
    
    // Super.so (Notion sites)
    "super": {
        "super.site",
        "super.so",
    },
    
    // Read the Docs
    "readthedocs": {
        "readthedocs.io",
        "readthedocs-hosted.com",
    },
    
    // GitBook
    "gitbook": {
        "gitbook.io",
        "gitbook.com",
    },
    
    // Docusaurus
    "docusaurus": {
        "docusaurus.io",
        "docusaurus.com",
    },
    
    // AWS Route53
    "route53": {
        "amazonaws.com", // Specifically for Route53 hosted zones
    },
    
    // Cloudinary
    "cloudinary": {
        "cloudinary.com",
        "cloudinary.net",
    },
    
    // Imgix
    "imgix": {
        "imgix.net",
        "imgix.com",
    },
    
    // Uploadcare
    "uploadcare": {
        "uploadcare.com",
        "ucarecdn.com",
    },
    
    // BunnyCDN
    "bunnycdn": {
        "bunny.net",
        "b-cdn.net",
    },
    
    // KeyCDN
    "keycdn": {
        "keycdn.com",
        "kxcdn.com",
    },
    
    // Backblaze B2
    "backblaze": {
        "backblazeb2.com",
        "b2cdn.com",
    },
    
    // Wasabi
    "wasabi": {
        "wasabisys.com",
        "wasabiapp.com",
    },
    
    // DreamHost
    "dreamhost": {
        "dreamhosters.com",
        "dreamhost.com",
    },
    
    // SiteGround
    "siteground": {
        "siteground.net",
        "siteground.eu",
    },
    
    // WP Engine
    "wpengine": {
        "wpengine.com",
        "wpenginepowered.com",
    },
    
    // Kinsta
    "kinsta": {
        "kinsta.com",
        "kinstacdn.com",
    },
    
    // Fly.io
    "fly": {
        "fly.dev",
        "fly.io",
    },
    
    // Railway
    "railway": {
        "railway.app",
        "railway.railway.app",
    },
    
    // Render
    "render": {
        "onrender.com",
        "render.com",
    },
    
    // Platform.sh
    "platformsh": {
        "platformsh.site",
        "platformsh.net",
    },
    
    // Dokku
    "dokku": {
        "dokku.me",
        "dokkuapp.com",
    },
    
    // Coolify
    "coolify": {
        "coolify.io",
        "coolify.app",
    },
    
    // CapRover
    "caprover": {
        "caprover.com",
        "caprover.cloud",
    },
    
    // Plesk
    "plesk": {
        "plesk.page",
        "plesk.com",
    },
    
    // cPanel
    "cpanel": {
        "cpanel.net",
        "cpanel.com",
    },
    
    // Duda
    "duda": {
        "duda.co",
        "dudaui.com",
    },
    
    // Weebly
    "weebly": {
        "weebly.com",
        "weeblysite.com",
    },
    
    // Jimdo
    "jimdo": {
        "jimdo.com",
        "jimdofree.com",
    },
    
    // 1&1 IONOS
    "ionos": {
        "ionos.com",
        "ionos.de",
    },
    
    // GoDaddy
    "godaddy": {
        "godaddy.com",
        "secureserver.net",
    },
    
    // Namecheap
    "namecheap": {
        "namecheap.com",
        "registrar-servers.com",
    },
    
    // HostGator
    "hostgator": {
        "hostgator.com",
        "hgator.com",
    },
    
    // Bluehost
    "bluehost": {
        "bluehost.com",
        "mybluehost.com",
    },
}

func init() {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        MaxIdleConns:    100,
        IdleConnTimeout: 90 * time.Second,
    }
    
    client = &http.Client{
        Transport: tr,
        Timeout:   30 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse // Don't follow redirects automatically
        },
    }
}

func main() {
    fmt.Println(`
    ███████╗██╗  ██╗██████╗ ██████╗ ███████╗███████╗████████╗
    ██╔════╝╚██╗██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝╚══██╔══╝
    ███████╗ ╚███╔╝ ██████╔╝██████╔╝█████╗  ███████╗   ██║   
    ╚════██║ ██╔██╗ ██╔═══╝ ██╔══██╗██╔══╝  ╚════██║   ██║   
    ███████║██╔╝ ██╗██║     ██║  ██║███████╗███████║   ██║   
    ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   
    
    Security Scanner: Redirect Analyzer, Subdomain Takeover & Clickjacking Detector
    `)

    // Get input
    var targets []string
    if len(os.Args) > 1 {
        if os.Args[1] == "-f" && len(os.Args) > 2 {
            targets = readFile(os.Args[2])
        } else {
            targets = os.Args[1:]
        }
    } else {
        scanner := bufio.NewScanner(os.Stdin)
        fmt.Println("Enter URLs (one per line, Ctrl+D to finish):")
        for scanner.Scan() {
            url := strings.TrimSpace(scanner.Text())
            if url != "" {
                targets = append(targets, url)
            }
        }
    }

    if len(targets) == 0 {
        fmt.Println("No targets provided")
        os.Exit(1)
    }

    fmt.Printf("Scanning %d targets...\n\n", len(targets))
    
    // Scan all targets concurrently
    resultChan := make(chan ScanResult, len(targets))
    
    for _, target := range targets {
        wg.Add(1)
        go func(url string) {
            defer wg.Done()
            result := scanURL(url)
            resultChan <- result
        }(normalizeURL(target))
    }
    
    go func() {
        wg.Wait()
        close(resultChan)
    }()
    
    // Collect results
    for result := range resultChan {
        results = append(results, result)
        printResult(result)
    }
    
    generateReport()
}

func readFile(filename string) []string {
    var lines []string
    file, err := os.Open(filename)
    if err != nil {
        fmt.Printf("Error reading file: %v\n", err)
        return lines
    }
    defer file.Close()
    
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        lines = append(lines, strings.TrimSpace(scanner.Text()))
    }
    return lines
}

func normalizeURL(rawURL string) string {
    if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
        return "https://" + rawURL
    }
    return rawURL
}

func scanURL(targetURL string) ScanResult {
    result := ScanResult{
        URL:    targetURL,
        Domain: extractDomain(targetURL),
    }
    
    // Follow redirects
    redirects, finalURL := followRedirects(targetURL)
    result.RedirectChain = redirects
    
    // Analyze for vulnerabilities
    vulnerabilities := []Vulnerability{}
    
    // Check subdomain takeover
    vulns := checkSubdomainTakeover(result.Domain, finalURL)
    vulnerabilities = append(vulnerabilities, vulns...)
    
    // Check clickjacking
    clickjackingVuln := checkClickjacking(finalURL)
    if clickjackingVuln.Type != "" {
        vulnerabilities = append(vulnerabilities, clickjackingVuln)
    }
    
    result.Vulnerabilities = vulnerabilities
    return result
}

func followRedirects(startURL string) ([]string, string) {
    var redirects []string
    currentURL := startURL
    visited := make(map[string]bool)
    
    for i := 0; i < 10; i++ { // Max 10 redirects
        if visited[currentURL] {
            break
        }
        visited[currentURL] = true
        
        req, err := http.NewRequest("GET", currentURL, nil)
        if err != nil {
            break
        }
        
        req.Header.Set("User-Agent", "Security-Scanner/1.0")
        
        resp, err := client.Do(req)
        if err != nil {
            break
        }
        defer resp.Body.Close()
        
        // Add to redirect chain
        redirects = append(redirects, fmt.Sprintf("%s -> %d", currentURL, resp.StatusCode))
        
        // Check for Location header
        location := resp.Header.Get("Location")
        if location == "" || resp.StatusCode < 300 || resp.StatusCode >= 400 {
            break
        }
        
        // Resolve relative URLs
        parsedCurrent, _ := url.Parse(currentURL)
        parsedLocation, err := url.Parse(location)
        if err != nil {
            break
        }
        
        if parsedLocation.Host == "" {
            parsedLocation.Host = parsedCurrent.Host
            parsedLocation.Scheme = parsedCurrent.Scheme
        }
        
        currentURL = parsedLocation.String()
    }
    
    return redirects, currentURL
}

func extractDomain(urlString string) string {
    parsed, err := url.Parse(urlString)
    if err != nil {
        return ""
    }
    
    // Remove port if present
    host := parsed.Hostname()
    if host == "" {
        return ""
    }
    
    // Extract root domain (simplified)
    parts := strings.Split(host, ".")
    if len(parts) >= 2 {
        return parts[len(parts)-2] + "." + parts[len(parts)-1]
    }
    return host
}

func checkSubdomainTakeover(domain, finalURL string) []Vulnerability {
    var vulnerabilities []Vulnerability
    
    parsed, err := url.Parse(finalURL)
    if err != nil {
        return vulnerabilities
    }
    
    hostname := parsed.Hostname()
    if hostname == "" {
        return vulnerabilities
    }
    
    // Make a request to analyze the response
    req, err := http.NewRequest("GET", finalURL, nil)
    if err != nil {
        return vulnerabilities
    }
    req.Header.Set("User-Agent", "Security-Scanner/1.0")
    
    resp, err := client.Do(req)
    if err != nil {
        return vulnerabilities
    }
    defer resp.Body.Close()
    
    // Read response body once
    bodyBytes, _ := io.ReadAll(resp.Body)
    bodyStr := string(bodyBytes)
    
    // Check against known takeover services with enhanced detection
    for service, patterns := range takeoverServices {
        for _, pattern := range patterns {
            if strings.Contains(hostname, pattern) {
                vuln := analyzeServiceForTakeover(service, pattern, hostname, resp, bodyStr)
                if vuln.Type != "" {
                    vulnerabilities = append(vulnerabilities, vuln)
                }
            }
        }
    }
    
    // Additional check for generic takeover indicators
    if isGenericTakeoverIndicator(resp, bodyStr, hostname) {
        vuln := Vulnerability{
            Type:        "Subdomain Takeover",
            Severity:    "LOW",
            Description: "Generic takeover indicators detected",
            Evidence:    fmt.Sprintf("Hostname: %s | Status: %d | Indicators: Error page or default content", 
                                   hostname, resp.StatusCode),
        }
        vulnerabilities = append(vulnerabilities, vuln)
    }
    
    // Check for DNS-related takeover possibilities
    dnsVulns := checkDNSTakeoverIndicators(hostname, domain)
    vulnerabilities = append(vulnerabilities, dnsVulns...)
    
    return vulnerabilities
}

func analyzeServiceForTakeover(service, pattern, hostname string, resp *http.Response, bodyStr string) Vulnerability {
    baseEvidence := fmt.Sprintf("Domain: %s | Service: %s | Pattern: %s | Status: %d", 
                              hostname, service, pattern, resp.StatusCode)
    
    // Service-specific detection logic
    switch service {
    case "aws":
        if strings.Contains(hostname, "s3") || strings.Contains(hostname, "cloudfront") {
            if strings.Contains(bodyStr, "NoSuchBucket") ||
               strings.Contains(bodyStr, "AccessDenied") ||
               strings.Contains(bodyStr, "PermanentRedirect") ||
               strings.Contains(bodyStr, "The specified bucket does not exist") {
                return Vulnerability{
                    Type:        "Subdomain Takeover",
                    Severity:    "HIGH",
                    Description: "AWS S3/CloudFront bucket potentially vulnerable to takeover",
                    Evidence:    baseEvidence + " | AWS Error: " + extractAWSError(bodyStr),
                }
            }
        }
        if strings.Contains(bodyStr, "AWS") || strings.Contains(bodyStr, "amazonaws.com") {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "MEDIUM",
                Description: "AWS service detected, possible misconfiguration",
                Evidence:    baseEvidence,
            }
        }
        
    case "github":
        if resp.StatusCode == 404 && strings.Contains(hostname, "github.io") {
            // Additional GitHub-specific checks
            if strings.Contains(bodyStr, "There isn't a GitHub Pages site here") ||
               strings.Contains(bodyStr, "404 File not found") {
                return Vulnerability{
                    Type:        "Subdomain Takeover",
                    Severity:    "HIGH",
                    Description: "GitHub Pages site not configured",
                    Evidence:    baseEvidence + " | GitHub 404 page detected",
                }
            }
        }
        return Vulnerability{
            Type:        "Subdomain Takeover",
            Severity:    "MEDIUM",
            Description: "GitHub service domain detected",
            Evidence:    baseEvidence,
        }
        
    case "firebase":
        if strings.Contains(bodyStr, "Firebase Hosting Setup") ||
           strings.Contains(bodyStr, "Site not found") ||
           strings.Contains(bodyStr, "firebase.google.com") {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "HIGH",
                Description: "Firebase Hosting not configured",
                Evidence:    baseEvidence + " | Firebase setup page detected",
            }
        }
        
    case "heroku":
        if strings.Contains(bodyStr, "No such app") ||
           strings.Contains(bodyStr, "Heroku | No such app") ||
           resp.StatusCode == 404 {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "HIGH",
                Description: "Heroku app not found",
                Evidence:    baseEvidence + " | Heroku error page",
            }
        }
        
    case "azure":
        if strings.Contains(bodyStr, "Microsoft Azure") ||
           strings.Contains(bodyStr, "App Service") ||
           resp.StatusCode == 404 {
            // Azure specific error patterns
            if strings.Contains(bodyStr, "The web app you have attempted to reach") ||
               strings.Contains(bodyStr, "does not exist") {
                return Vulnerability{
                    Type:        "Subdomain Takeover",
                    Severity:    "HIGH",
                    Description: "Azure Web App not configured",
                    Evidence:    baseEvidence + " | Azure error page",
                }
            }
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "MEDIUM",
                Description: "Azure service detected",
                Evidence:    baseEvidence,
            }
        }
        
    case "fastly":
        if strings.Contains(bodyStr, "Fastly error: unknown domain") ||
           strings.Contains(bodyStr, "Please check that this domain has been added to a service") {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "HIGH",
                Description: "Fastly domain not configured",
                Evidence:    baseEvidence + " | Fastly error page",
            }
        }
        
    case "shopify":
        if strings.Contains(bodyStr, "Sorry, this shop is currently unavailable") ||
           strings.Contains(bodyStr, "There is nothing here") {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "HIGH",
                Description: "Shopify store not configured",
                Evidence:    baseEvidence + " | Shopify unavailable page",
            }
        }
        
    case "netlify":
        if strings.Contains(bodyStr, "Not Found - Request ID") ||
           strings.Contains(bodyStr, "netlify.com") && resp.StatusCode == 404 {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "HIGH",
                Description: "Netlify site not deployed",
                Evidence:    baseEvidence + " | Netlify 404 page",
            }
        }
        
    case "vercel", "zeit":
        if strings.Contains(bodyStr, "404: This page could not be found") ||
           strings.Contains(bodyStr, "The deployment could not be found") {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "HIGH",
                Description: "Vercel deployment not found",
                Evidence:    baseEvidence + " | Vercel 404 page",
            }
        }
        
    case "cloudflare":
        if strings.Contains(bodyStr, "404 Not Found") && 
           (strings.Contains(hostname, "pages.dev") || strings.Contains(hostname, "workers.dev")) {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "HIGH",
                Description: "Cloudflare Pages/Workers not configured",
                Evidence:    baseEvidence + " | Cloudflare 404",
            }
        }
        
    case "google":
        if strings.Contains(bodyStr, "The requested URL was not found on this server") &&
           strings.Contains(hostname, "appspot.com") {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "HIGH",
                Description: "Google App Engine app not deployed",
                Evidence:    baseEvidence + " | GAE 404",
            }
        }
        
    case "wix":
        if strings.Contains(bodyStr, "This site is not yet published") ||
           strings.Contains(bodyStr, "wix.com") && resp.StatusCode == 404 {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "HIGH",
                Description: "Wix site not published",
                Evidence:    baseEvidence + " | Wix unpublished page",
            }
        }
        
    case "squarespace":
        if strings.Contains(bodyStr, "This site is not available") ||
           strings.Contains(bodyStr, "squarespace.com") && resp.StatusCode == 404 {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "HIGH",
                Description: "Squarespace site not configured",
                Evidence:    baseEvidence + " | Squarespace unavailable",
            }
        }
        
    case "wordpress", "wpengine":
        if strings.Contains(bodyStr, "Do you want to register") ||
           strings.Contains(bodyStr, "wordpress.com") && resp.StatusCode == 404 {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "MEDIUM",
                Description: "WordPress.com site not registered",
                Evidence:    baseEvidence,
            }
        }
        
    case "gitlab":
        if resp.StatusCode == 404 && strings.Contains(hostname, "gitlab.io") {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "HIGH",
                Description: "GitLab Pages site not configured",
                Evidence:    baseEvidence + " | GitLab 404",
            }
        }
        
    case "bitbucket":
        if resp.StatusCode == 404 && strings.Contains(hostname, "bitbucket.io") {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "HIGH",
                Description: "Bitbucket site not configured",
                Evidence:    baseEvidence + " | Bitbucket 404",
            }
        }
        
    case "readthedocs":
        if strings.Contains(bodyStr, "Read the Docs") && 
           (strings.Contains(bodyStr, "project doesn't exist") || resp.StatusCode == 404) {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "HIGH",
                Description: "Read the Docs project not configured",
                Evidence:    baseEvidence + " | Read the Docs error",
            }
        }
        
    case "helpjuice", "helpscout", "zendesk", "intercom":
        if resp.StatusCode == 404 || resp.StatusCode == 503 {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "MEDIUM",
                Description: fmt.Sprintf("%s help desk/portal potentially misconfigured", service),
                Evidence:    baseEvidence + " | Service error page",
            }
        }
        
    default:
        // Generic detection for other services
        if isServiceErrorPage(resp, bodyStr) {
            return Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "MEDIUM",
                Description: fmt.Sprintf("%s service potentially misconfigured", service),
                Evidence:    baseEvidence + " | Service error detected",
            }
        }
        return Vulnerability{
            Type:        "Subdomain Takeover",
            Severity:    "LOW",
            Description: fmt.Sprintf("%s service domain detected", service),
            Evidence:    baseEvidence,
        }
    }
    
    return Vulnerability{} // Empty vulnerability if no match
}

func extractAWSError(body string) string {
    errorPatterns := []string{
        "NoSuchBucket",
        "AccessDenied",
        "PermanentRedirect",
        "The specified bucket does not exist",
        "InvalidBucketName",
        "BucketAlreadyExists",
    }
    
    for _, pattern := range errorPatterns {
        if strings.Contains(body, pattern) {
            return pattern
        }
    }
    return "Unknown AWS Error"
}

func isServiceErrorPage(resp *http.Response, bodyStr string) bool {
    // Common error indicators across services
    errorIndicators := []string{
        "error",
        "not found",
        "not available",
        "does not exist",
        "unavailable",
        "404",
        "503",
        "service",
        "deployment",
        "configure",
        "setup",
        "register",
    }
    
    // Check status code
    if resp.StatusCode >= 400 && resp.StatusCode < 600 {
        // Check body for error messages
        lowerBody := strings.ToLower(bodyStr)
        count := 0
        for _, indicator := range errorIndicators {
            if strings.Contains(lowerBody, indicator) {
                count++
            }
        }
        return count >= 2 // At least two error indicators
    }
    
    return false
}

func isGenericTakeoverIndicator(resp *http.Response, bodyStr, hostname string) bool {
    // Check for generic takeover indicators
    if resp.StatusCode == 404 || resp.StatusCode == 503 || resp.StatusCode == 502 {
        // Check for default/error pages that might indicate takeover potential
        defaultPageIndicators := []string{
            "default page",
            "welcome to",
            "apache",
            "nginx",
            "iis",
            "test page",
            "coming soon",
            "under construction",
            "placeholder",
        }
        
        lowerBody := strings.ToLower(bodyStr)
        for _, indicator := range defaultPageIndicators {
            if strings.Contains(lowerBody, indicator) {
                return true
            }
        }
    }
    
    // Check for empty or very small responses
    if len(bodyStr) < 100 && resp.StatusCode == 200 {
        return true
    }
    
    return false
}

func checkDNSTakeoverIndicators(hostname, domain string) []Vulnerability {
    var vulnerabilities []Vulnerability
    
    // Check for suspicious domain patterns
    suspiciousPatterns := []string{
        "-test", "-dev", "-staging", "-qa",
        "test-", "dev-", "staging-", "uat-",
        ".test.", ".dev.", ".staging.",
    }
    
    for _, pattern := range suspiciousPatterns {
        if strings.Contains(hostname, pattern) {
            vuln := Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "LOW",
                Description: "Test/development subdomain detected - higher takeover risk",
                Evidence:    fmt.Sprintf("Hostname contains '%s' pattern: %s", pattern, hostname),
            }
            vulnerabilities = append(vulnerabilities, vuln)
        }
    }
    
    // Check for orphaned subdomain patterns
    orphanedPatterns := []string{
        "old-", "legacy-", "deprecated-", "archive-",
        "backup-", "temp-", "tmp-", "demo-",
    }
    
    for _, pattern := range orphanedPatterns {
        if strings.Contains(hostname, pattern) {
            vuln := Vulnerability{
                Type:        "Subdomain Takeover",
                Severity:    "MEDIUM",
                Description: "Orphaned/legacy subdomain detected - possible takeover candidate",
                Evidence:    fmt.Sprintf("Hostname contains orphaned pattern '%s': %s", pattern, hostname),
            }
            vulnerabilities = append(vulnerabilities, vuln)
        }
    }
    
    return vulnerabilities
}

// Helper function to make the GitHub check more robust
func checkGitHubPageExists(hostname string) bool {
    if !strings.Contains(hostname, "github.io") {
        return false
    }
    
    // Try to access the GitHub page
    url := fmt.Sprintf("https://%s", hostname)
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return false
    }
    
    resp, err := client.Do(req)
    if err != nil {
        return false
    }
    defer resp.Body.Close()
    
    body, _ := io.ReadAll(resp.Body)
    bodyStr := string(body)
    
    // GitHub Pages 404 indicators
    return resp.StatusCode == 404 && 
           (strings.Contains(bodyStr, "There isn't a GitHub Pages site here") ||
            strings.Contains(bodyStr, "404 File not found"))
}

// Enhanced CNAME detection
func hasExternalCNAME(hostname string) bool {
    externalPatterns := []string{
        // Cloud providers
        "aws", "amazon", "azure", "google", "gcp", 
        "cloudflare", "fastly", "akamai",
        // PaaS/SaaS
        "heroku", "netlify", "vercel", "zeit", "firebase",
        "shopify", "wix", "squarespace", "wordpress",
        "gitlab", "bitbucket", "gh", "gl", "bb",
        // CDNs
        "cdn", "edge", "static", "assets",
        // Generic
        "external", "thirdparty", "3rdparty", "outsource",
    }
    
    lowerHostname := strings.ToLower(hostname)
    
    for _, pattern := range externalPatterns {
        if strings.Contains(lowerHostname, pattern) {
            return true
        }
    }
    
    // Check for domain mismatch (subdomain pointing to completely different domain)
    parts := strings.Split(hostname, ".")
    if len(parts) >= 3 {
        // If the domain ends with a known service domain but has different parent
        for service := range takeoverServices {
            for _, serviceDomain := range takeoverServices[service] {
                if strings.HasSuffix(hostname, serviceDomain) {
                    return true
                }
            }
        }
    }
    
    return false
}





func checkClickjacking(targetURL string) Vulnerability {
    req, err := http.NewRequest("GET", targetURL, nil)
    if err != nil {
        return Vulnerability{}
    }
    
    resp, err := client.Do(req)
    if err != nil {
        return Vulnerability{}
    }
    defer resp.Body.Close()
    
    // Check for X-Frame-Options header
    xFrameOptions := resp.Header.Get("X-Frame-Options")
    frameAncestors := resp.Header.Get("Content-Security-Policy")
    
    if xFrameOptions == "" && !strings.Contains(strings.ToLower(frameAncestors), "frame-ancestors") {
        return Vulnerability{
            Type:        "Clickjacking",
            Severity:    "MEDIUM",
            Description: "Missing X-Frame-Options or CSP frame-ancestors header",
            Evidence:    "No frame-busting headers detected",
        }
    }
    
    if xFrameOptions != "" && strings.ToUpper(xFrameOptions) != "DENY" && 
       strings.ToUpper(xFrameOptions) != "SAMEORIGIN" {
        return Vulnerability{
            Type:        "Clickjacking",
            Severity:    "LOW",
            Description: "Weak X-Frame-Options configuration",
            Evidence:    fmt.Sprintf("X-Frame-Options: %s", xFrameOptions),
        }
    }
    
    return Vulnerability{}
}

func printResult(result ScanResult) {
    fmt.Printf("\n" + strings.Repeat("=", 80) + "\n")
    fmt.Printf("URL: %s\n", result.URL)
    fmt.Printf("Domain: %s\n", result.Domain)
    
    if len(result.RedirectChain) > 0 {
        fmt.Println("\nRedirect Chain:")
        for i, redirect := range result.RedirectChain {
            fmt.Printf("  %d. %s\n", i+1, redirect)
        }
    }
    
    if len(result.Vulnerabilities) > 0 {
        fmt.Println("\n⚠️  VULNERABILITIES FOUND:")
        for _, vuln := range result.Vulnerabilities {
            fmt.Printf("  [%s] %s: %s\n", vuln.Severity, vuln.Type, vuln.Description)
            if vuln.Evidence != "" {
                fmt.Printf("    Evidence: %s\n", vuln.Evidence)
            }
        }
    } else {
        fmt.Println("\n✅ No vulnerabilities found")
    }
}

func generateReport() {
    fmt.Printf("\n" + strings.Repeat("=", 80) + "\n")
    fmt.Println("SCAN SUMMARY")
    fmt.Println(strings.Repeat("=", 80))
    
    totalVulns := 0
    vulnByType := make(map[string]int)
    vulnBySeverity := make(map[string]int)
    
    for _, result := range results {
        for _, vuln := range result.Vulnerabilities {
            totalVulns++
            vulnByType[vuln.Type]++
            vulnBySeverity[vuln.Severity]++
        }
    }
    
    fmt.Printf("Total URLs scanned: %d\n", len(results))
    fmt.Printf("Total vulnerabilities found: %d\n", totalVulns)
    
    if totalVulns > 0 {
        fmt.Println("\nVulnerabilities by type:")
        for vulnType, count := range vulnByType {
            fmt.Printf("  %s: %d\n", vulnType, count)
        }
        
        fmt.Println("\nVulnerabilities by severity:")
        for severity, count := range vulnBySeverity {
            fmt.Printf("  %s: %d\n", severity, count)
        }
        
        fmt.Println("\nVulnerable URLs:")
        for _, result := range results {
            if len(result.Vulnerabilities) > 0 {
                fmt.Printf("  %s\n", result.URL)
                for _, vuln := range result.Vulnerabilities {
                    fmt.Printf("    - [%s] %s\n", vuln.Severity, vuln.Type)
                }
            }
        }
    }
    
    // Save to file
    saveReportToFile()
}

func saveReportToFile() {
    timestamp := time.Now().Format("2006-01-02_15-04-05")
    filename := fmt.Sprintf("security_scan_%s.txt", timestamp)
    
    file, err := os.Create(filename)
    if err != nil {
        fmt.Printf("Error creating report file: %v\n", err)
        return
    }
    defer file.Close()
    
    writer := bufio.NewWriter(file)
    
    writer.WriteString(fmt.Sprintf("Security Scan Report - %s\n", time.Now().Format("2006-01-02 15:04:05")))
    writer.WriteString(strings.Repeat("=", 80) + "\n\n")
    
    for _, result := range results {
        writer.WriteString(fmt.Sprintf("URL: %s\n", result.URL))
        writer.WriteString(fmt.Sprintf("Domain: %s\n", result.Domain))
        
        if len(result.RedirectChain) > 0 {
            writer.WriteString("Redirect Chain:\n")
            for i, redirect := range result.RedirectChain {
                writer.WriteString(fmt.Sprintf("  %d. %s\n", i+1, redirect))
            }
        }
        
        if len(result.Vulnerabilities) > 0 {
            writer.WriteString("Vulnerabilities:\n")
            for _, vuln := range result.Vulnerabilities {
                writer.WriteString(fmt.Sprintf("  [%s] %s\n", vuln.Severity, vuln.Type))
                writer.WriteString(fmt.Sprintf("    Description: %s\n", vuln.Description))
                writer.WriteString(fmt.Sprintf("    Evidence: %s\n", vuln.Evidence))
            }
        }
        writer.WriteString("\n" + strings.Repeat("-", 80) + "\n\n")
    }
    
    writer.Flush()
    fmt.Printf("\nReport saved to: %s\n", filename)
}

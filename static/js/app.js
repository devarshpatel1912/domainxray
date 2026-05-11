/* ============================================
   DomainXray - Frontend JavaScript
   ============================================ */

let currentDomain = '';
let currentIP = '';
let dnsRecords = [];
let subdomainResults = [];
let mapInstance = null;
let tabDataLoaded = {};

// ============================================
// Theme Management
// ============================================

function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    if (savedTheme === 'light') {
        document.body.classList.add('light-mode');
    }
    updateThemeIcon();
}

function toggleTheme() {
    const isLight = document.body.classList.toggle('light-mode');
    localStorage.setItem('theme', isLight ? 'light' : 'dark');
    updateThemeIcon();
}

function updateThemeIcon() {
    const isLight = document.body.classList.contains('light-mode');
    const btns = document.querySelectorAll('.theme-toggle-btn');
    
    btns.forEach(btn => {
        if (isLight) {
            btn.innerHTML = `
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
                </svg>`;
            btn.title = "Switch to Dark Mode";
        } else {
            btn.innerHTML = `
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="5"></circle>
                    <line x1="12" y1="1" x2="12" y2="3"></line>
                    <line x1="12" y1="21" x2="12" y2="23"></line>
                    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
                    <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
                    <line x1="1" y1="12" x2="3" y2="12"></line>
                    <line x1="21" y1="12" x2="23" y2="12"></line>
                    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
                    <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
                </svg>`;
            btn.title = "Switch to Light Mode";
        }
    });
}

function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });
    
    // Update mobile bottom nav items
    document.querySelectorAll('.mobile-nav-item').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
        if (btn.dataset.tab === tabName) {
            btn.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
        }
    });
    
    // Update tab panels
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.toggle('active', panel.id === `tab-${tabName}`);
    });
    
    // Lazy-load tab data if needed

    if (tabName === 'ssl' && !tabDataLoaded.ssl) {
        loadSSLDetails(currentDomain);
    }
    if (tabName === 'security' && !tabDataLoaded.security) {
        loadSecurity(currentDomain);
    }
    if (tabName === 'mail' && !tabDataLoaded.mail) {
        loadMailForensics(currentDomain);
    }
    if (tabName === 'threatintel' && !tabDataLoaded.threatintel) {
        loadThreatIntel(currentDomain);
    }
    if (tabName === 'monitoring' && !tabDataLoaded.monitoring) {
        loadMonitoring(currentDomain);
    }
}

// ============================================
// Init Scan
// ============================================

function initScan(domain) {
    currentDomain = domain;
    tabDataLoaded = {};
    initTheme();
    
    // Load overview data (WHOIS + IP + SSL)
    loadOverview(domain);
    
    // Load DNS records (DNS changes are often slower, but we can add force here too if needed)
    loadDNS(domain);
    
    // Load security checks
    loadSecurity(domain);
    
    // Load history
    loadHistory(domain);
    
    // Load AI insights
    loadAIInsights(domain);
    
    // Load tech stack

}

// ============================================
// Overview Tab
// ============================================

function loadOverview(domain, force = false) {
    return fetch(`/api/scan/overview/${domain}${force ? '?force=true' : ''}`)
        .then(r => r.json())
        .then(data => {
            renderDomainHeader(data);
            renderDomainInfo(data.whois);
            renderIPHosting(data.ip, data.whois);
            renderSSLSummary(data.ssl);
            
            // Site Analysis / Heading Forensics (New)
            renderHeadingAnalysis(domain); 
            
            if (data.ip && data.ip.ipv4) {
                currentIP = data.ip.ipv4;
            }
        })
        .catch(err => {
            console.error('Overview error:', err);
        });
}

function renderDomainHeader(data) {
    const whois = data.whois;
    const ip = data.ip;
    
    // Status badge
    const badge = document.getElementById('statusBadge');
    const statusText = document.getElementById('statusText');
    if (whois.is_active) {
        statusText.textContent = 'Active';
        badge.classList.remove('expired');
    } else {
        statusText.textContent = 'Expired';
        badge.classList.add('expired');
    }
    
    // Meta info
    const metaLocation = document.getElementById('metaLocation');
    const metaIP = document.getElementById('metaIP');
    const metaAge = document.getElementById('metaAge');
    
    if (ip.info && ip.info.city) {
        metaLocation.querySelector('span').textContent = `${ip.info.city}, ${ip.info.country || ''}`;
    } else {
        metaLocation.querySelector('span').textContent = 'Unknown';
    }
    
    if (ip.ipv4) {
        metaIP.querySelector('span').textContent = ip.ipv4;
    }
    
    if (whois.domain_age) {
        metaAge.querySelector('span').textContent = `Age: ${whois.domain_age}`;
    }
}

function renderDomainInfo(whois) {
    const body = document.getElementById('domainInfoBody');
    const badge = document.getElementById('verifiedBadge');
    
    if (whois.registrar) {
        badge.style.display = 'inline-block';
    }
    
    const reg = whois.registrant || {};
    const registrantAddress = [reg.city, reg.state, reg.country].filter(Boolean).join(', ');

    let html = `
        <div class="info-row">
            <span class="info-label">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
                </svg>
                Registrar
            </span>
            <span class="info-value">${whois.registrar || 'Unknown'}</span>
        </div>
        <div class="info-row">
            <span class="info-label">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>
                </svg>
                Created
            </span>
            <span class="info-value">${whois.creation_date_formatted || 'N/A'}</span>
        </div>
        <div class="info-row">
            <span class="info-label">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
                </svg>
                Expires
            </span>
            <span class="info-value ${getExpiryClass(whois.expiration_date_formatted)}">${whois.expiration_date_formatted || 'N/A'}</span>
        </div>
        <div class="info-row">
            <span class="info-label">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                Domain Age
            </span>
            <span class="info-value">${whois.domain_age || 'N/A'}</span>
        </div>
        <div class="info-row" title="Physical address from WHOIS">
            <span class="info-label">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/>
                </svg>
                Registrant
            </span>
            <span class="info-value" style="color: var(--cyan); text-align: right; font-size: 0.82rem;">
                ${reg.organization ? `<strong>${reg.organization}</strong><br>` : ''}
                ${registrantAddress || 'Private'}
            </span>
        </div>
    `;
    
    // Nameservers
    if (whois.nameservers && whois.nameservers.length > 0) {
        html += `<div class="nameserver-list">
            <div class="nameserver-label">Nameservers</div>`;
        whois.nameservers.forEach(ns => {
            html += `<div class="nameserver-item">${ns}</div>`;
        });
        html += `</div>`;
    }
    
    body.innerHTML = html;
}

function renderIPHosting(ip, whois) {
    const body = document.getElementById('ipHostingBody');
    const info = ip.info || {};
    const reg = whois ? (whois.registrant || {}) : {};
    const whoisLoc = [reg.city, reg.state, reg.country].filter(Boolean).join(', ');
    const origin = ip.origin;
    
    let html = `
        <div class="ip-display">${ip.ipv4 || 'N/A'}</div>
        <div class="ipv6-display">${ip.ipv6 ? `IPv6: ${ip.ipv6}` : ''}</div>
    `;
    
    // Map
    if (info.lat && info.lon) {
        html += `<div class="map-container" id="ipMap"></div>`;
    }
    
    // Location details
    html += `
        <div class="info-row">
            <span class="info-label">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>
                    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                </svg>
                Hosting/ISP
            </span>
            <span class="info-value">${info.hosting || 'Unknown'}</span>
        </div>
        <div class="info-row">
            <span class="info-label">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>
                </svg>
                Location
            </span>
            <span class="info-value">${info.city ? info.city + ', ' + info.country : 'Unknown'}</span>
        </div>
        ${whoisLoc ? `
        <div class="info-row">
            <span class="info-label">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/>
                </svg>
                Whois Loc
            </span>
            <span class="info-value">${whoisLoc}</span>
        </div>` : ''}
    `;
    body.innerHTML = html;
}

function renderSSL(ssl) {
    // Legacy function, redirects to summary
    renderSSLSummary(ssl);
}

function renderSSLSummary(ssl) {
    const body = document.getElementById('sslBody');
    const badge = document.getElementById('sslBadge');
    
    if (ssl.error && !ssl.valid) {
        badge.style.display = 'inline-block';
        badge.textContent = 'Invalid';
        badge.classList.add('invalid');
        body.innerHTML = `<p style="color: var(--red); text-align: center; padding: 20px;">${ssl.error}</p>`;
        return;
    }
    
    badge.style.display = 'none'; // Using internal badge now
    
    const days = ssl.days_remaining || 0;
    const pct = Math.min(days / 365, 1);
    const circumference = 2 * Math.PI * 34;
    const offset = circumference - (pct * circumference);
    const gaugeColor = days > 90 ? '#22c55e' : days > 30 ? '#f59e0b' : '#ef4444';
    
    body.innerHTML = `
        <div class="ssl-summary-card-inner">
            <div class="ssl-overview-header">
                <div class="ssl-grade-a">${(ssl.grade || 'F').toUpperCase()}</div>
                <div class="ssl-valid-badge">${ssl.valid ? 'Valid' : 'Invalid'}</div>
            </div>
            
            <div class="ssl-gauge-main">
                <div class="ssl-gauge-circle-container">
                    <svg width="80" height="80" viewBox="0 0 80 80">
                        <circle class="ssl-gauge-circle-bg" cx="40" cy="40" r="34" />
                        <circle class="ssl-gauge-circle-fill" cx="40" cy="40" r="34" 
                                style="stroke-dasharray: ${circumference}; stroke-dashoffset: ${offset}; stroke: ${gaugeColor};"
                                transform="rotate(-90 40 40)" />
                    </svg>
                    <div class="ssl-gauge-days-overlay">
                        <span class="ssl-gauge-days-val">${days}</span>
                        <span class="ssl-gauge-label">days</span>
                    </div>
                </div>
                <div class="ssl-gauge-info">
                    <span class="ssl-status-text" style="color: ${gaugeColor}">${ssl.valid ? 'Safe' : 'Risk'}</span>
                    <span class="ssl-date-text">Expires ${ssl.expiry_date}</span>
                    <span class="ssl-date-text">Issued ${ssl.issued_date}</span>
                </div>
            </div>
            
            <div class="ssl-info-rows">
                <div class="ssl-info-row">
                    <span class="ssl-info-label">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        Issuer
                    </span>
                    <span class="ssl-info-value">${ssl.issuer || 'Unknown'}</span>
                </div>
                <div class="ssl-info-row">
                    <span class="ssl-info-label">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                        Protocol
                    </span>
                    <span class="ssl-info-value">${ssl.protocol || 'Unknown'}</span>
                </div>
                <div class="ssl-info-row">
                    <span class="ssl-info-label">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3y-3z"/></svg>
                        Algorithm
                    </span>
                    <span class="ssl-info-value">${ssl.cipher_suite || ssl.algorithm || 'Unknown'}</span>
                </div>
                <div class="ssl-info-row">
                    <span class="ssl-info-label">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
                        Wildcard
                    </span>
                    <span class="ssl-info-value">${ssl.wildcard ? 'Yes' : 'No'}</span>
                </div>
            </div>
            
            <a href="javascript:void(0)" onclick="switchTab('ssl')" class="ssl-tab-link">
                Go to the SSL tab for full details
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
            </a>
        </div>
    `;
}

function loadSSLDetails(domain) {
    // Reuse overview data if possible, or fetch again for full forensic details
    fetch(`/api/scan/overview/${domain}`)
        .then(r => r.json())
        .then(data => {
            renderSSLFull(data.ssl);
            tabDataLoaded.ssl = true;
        });
}

function renderSSLFull(ssl) {
    const container = document.getElementById('sslFullDetails');
    if (!ssl) return;

    const days = ssl.days_remaining || 0;
    const circumference = 2 * Math.PI * 50;
    const pct = Math.min(days / 365, 1);
    const offset = circumference - (pct * circumference);
    const gaugeColor = days > 90 ? '#22c55e' : days > 30 ? '#f59e0b' : '#ef4444';

    let html = `
        <div class="ssl-full-container">
            <!-- Premium Header -->
            <div class="ssl-header-premium">
                <div class="ssl-header-title">
                    <h2>SSL Certificate</h2>
                    <span class="ssl-header-subtitle">Security overview & encryption forensics</span>
                </div>
                <div class="ssl-grade-large">
                    <span class="ssl-header-subtitle">Security Grade:</span>
                    <div class="grade-badge-xl">${(ssl.grade || 'F').toUpperCase()}</div>
                    <div class="ssl-status-pill">${ssl.valid ? 'Valid' : 'Invalid'}</div>
                </div>
            </div>

            <!-- Gauge & Info Panel -->
            <div class="ssl-tab-grid-top">
                <div class="ssl-gauge-panel-premium">
                    <div class="ssl-circle-lg">
                        <svg width="120" height="120" viewBox="0 0 120 120">
                            <circle class="ssl-gauge-circle-bg" cx="60" cy="60" r="50" style="stroke-width: 8;" />
                            <circle class="ssl-gauge-circle-fill" cx="60" cy="60" r="50" 
                                    style="stroke-dasharray: ${circumference}; stroke-dashoffset: ${offset}; stroke: ${gaugeColor}; stroke-width: 8;"
                                    transform="rotate(-90 60 60)" />
                        </svg>
                        <div class="ssl-circle-lg-text">
                            <span class="ssl-circle-days-val">${days}</span>
                            <span class="ssl-circle-days-label">days left</span>
                        </div>
                    </div>
                    <div class="ssl-gauge-details-premium">
                        <span class="ssl-safe-text" style="color: ${gaugeColor}">${ssl.valid ? 'Safe' : 'Risk'}</span>
                        <div class="ssl-expiry-info">
                            <span>Expires ${ssl.expiry_date}</span>
                            <span>Issued ${ssl.issued_date}</span>
                        </div>
                    </div>
                </div>

                <!-- Info Grid -->
                <div class="ssl-info-rows" style="background: var(--bg-card); padding: 2rem; border-radius: var(--radius-lg); border: 1px solid var(--border);">
                    <div class="ssl-info-row">
                        <span class="ssl-info-label">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                            Issuer
                        </span>
                        <span class="ssl-info-value" style="font-size: 1rem;">${ssl.issuer || 'Unknown'}</span>
                    </div>
                    <div class="ssl-info-row">
                        <span class="ssl-info-label">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                            Protocol
                        </span>
                        <span class="ssl-info-value" style="font-size: 1rem;">${ssl.protocol || 'Unknown'}</span>
                    </div>
                    <div class="ssl-info-row">
                        <span class="ssl-info-label">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3y-3z"/></svg>
                            Algorithm
                        </span>
                        <span class="ssl-info-value" style="font-size: 1rem;">${ssl.cipher_suite || ssl.algorithm || 'Unknown'}</span>
                    </div>
                    <div class="ssl-info-row">
                        <span class="ssl-info-label">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
                            Wildcard
                        </span>
                        <span class="ssl-info-value" style="font-size: 1rem;">${ssl.wildcard ? 'Yes' : 'No'}</span>
                    </div>
                </div>
            </div>

            <!-- Status Cards -->
            <div class="ssl-status-cards">
                <div class="ssl-status-card">
                    <div class="ssl-card-icon" style="background: rgba(34, 197, 94, 0.1); color: var(--green);">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                    </div>
                    <span class="ssl-card-title">HTTPS</span>
                    <span class="ssl-card-val" style="color: var(--green);">Enabled</span>
                </div>
                <div class="ssl-status-card">
                    <div class="ssl-card-icon" style="background: ${ssl.vulnerabilities?.['Weak SSL/TLS'] === 'Safe' ? 'rgba(34, 197, 94, 0.1)' : 'rgba(245, 158, 11, 0.1)'}; color: ${ssl.vulnerabilities?.['Weak SSL/TLS'] === 'Safe' ? 'var(--green)' : 'var(--orange)'};">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    </div>
                    <span class="ssl-card-title">HSTS</span>
                    <span class="ssl-card-val" style="color: ${ssl.vulnerabilities?.['Weak SSL/TLS'] === 'Safe' ? 'var(--green)' : 'var(--orange)'};">${ssl.vulnerabilities?.['Weak SSL/TLS'] === 'Safe' ? 'Enabled' : 'Missing'}</span>
                </div>
                <div class="ssl-status-card">
                    <div class="ssl-card-icon" style="background: ${ssl.chain_valid ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)'}; color: ${ssl.chain_valid ? 'var(--green)' : 'var(--red)'};">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                    </div>
                    <span class="ssl-card-title">Chain</span>
                    <span class="ssl-card-val" style="color: ${ssl.chain_valid ? 'var(--green)' : 'var(--red)'};">${ssl.chain_valid ? 'Valid' : 'Broken'}</span>
                </div>
            </div>

            <!-- Encryption Strength Bar -->
            <div class="ssl-encryption-section" style="background: var(--bg-card); padding: 2rem; border-radius: var(--radius-lg); border: 1px solid var(--border);">
                <div class="ssl-strength-header">
                    <div class="ssl-strength-label">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
                        Encryption Strength
                    </div>
                    <div class="ssl-strength-val">${ssl.cipher_suite || 'AES-256-GCM'} <span style="background: var(--green-dim); color: var(--green); padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; margin-left: 8px;">Strong</span></div>
                </div>
                <div class="ssl-strength-bar-bg">
                    <div class="ssl-strength-bar-fill" style="width: 100%;"></div>
                </div>
            </div>

            <!-- Security Summary -->
            <div class="ssl-summary-section">
                <div class="ssl-summary-title">Security Summary</div>
                <div class="ssl-summary-list">
                    <div class="ssl-summary-item">
                        <div class="ssl-summary-icon pass"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg></div>
                        <span>Strong AES-256-GCM encryption in use</span>
                    </div>
                    <div class="ssl-summary-item">
                        <div class="ssl-summary-icon pass"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg></div>
                        <span>${ssl.protocol} is the active protocol</span>
                    </div>
                    <div class="ssl-summary-item">
                        <div class="ssl-summary-icon pass"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg></div>
                        <span>Certificate chain is fully trusted</span>
                    </div>
                    <div class="ssl-summary-item">
                        <div class="ssl-summary-icon warn"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>
                        <span>HSTS header not configured</span>
                    </div>
                </div>
            </div>

            <!-- Accordions -->
            <div class="ssl-accordions">
                <div class="ssl-accordion collapsed">
                    <div class="ssl-accordion-header" onclick="toggleAccordion(this)">
                        <div class="ssl-accordion-title">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" stroke-width="2" style="opacity: 0.8;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                            Protocol Support
                        </div>
                        <svg class="arrow-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg>
                    </div>
                    <div class="ssl-accordion-body">
                        <div class="ssl-grid-list">
                            ${Object.entries(ssl.protocols || {}).map(([p, supported]) => `
                                <div class="ssl-grid-item">
                                    <span class="ssl-grid-label">${p}</span>
                                    <span class="ssl-status-badge-sm ${supported ? 'pass' : 'fail'}">
                                        ${supported ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg> Supported' : '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> Not Active'}
                                    </span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>

                <div class="ssl-accordion collapsed">
                    <div class="ssl-accordion-header" onclick="toggleAccordion(this)">
                        <div class="ssl-accordion-title">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" stroke-width="2" style="opacity: 0.8;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                            Vulnerability Check
                        </div>
                        <svg class="arrow-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg>
                    </div>
                    <div class="ssl-accordion-body">
                        <div class="ssl-grid-list">
                            ${Object.entries(ssl.vulnerabilities || {}).map(([v, status]) => `
                                <div class="ssl-grid-item">
                                    <span class="ssl-grid-label">${v}</span>
                                    <span class="ssl-status-badge-sm ${status === 'Safe' ? 'pass' : status === 'Warning' ? 'warn' : 'fail'}">
                                        ${status === 'Safe' ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg> Safe' : status}
                                    </span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    container.innerHTML = html;
}



function getExpiryClass(dateStr) {
    if (!dateStr || dateStr === 'N/A') return '';
    try {
        const expiry = new Date(dateStr);
        const now = new Date();
        const daysLeft = (expiry - now) / (1000 * 60 * 60 * 24);
        if (daysLeft < 0) return 'expired';
        if (daysLeft < 90) return 'expiry-soon';
        return 'safe';
    } catch {
        return '';
    }
}

// ============================================
// AI Insights
// ============================================

function loadAIInsights(domain) {
    fetch(`/api/scan/ai-insights/${domain}`)
        .then(r => r.json())
        .then(data => {
            renderAIInsights(data);
        })
        .catch(err => {
            console.error('AI Insights error:', err);
            document.getElementById('aiInsightsBody').innerHTML = `<p style="color: var(--text-muted); text-align: center; padding: 20px;">Could not generate AI insights</p>`;
        });
}

function renderAIInsights(data) {
    // Generated time
    document.getElementById('aiGeneratedTime').textContent = `Generated ${data.generated_at}`;

    // Risk Summary
    const riskEl = document.getElementById('aiRiskSummary');
    riskEl.innerHTML = `
        <span class="ai-risk-badge ${data.risk_class}">${data.risk_level}</span>
        <p class="ai-summary-text">${data.summary}</p>
    `;

    // Key Issues
    const issuesEl = document.getElementById('aiKeyIssues');
    if (data.key_issues && data.key_issues.length > 0) {
        issuesEl.innerHTML = data.key_issues.map(issue => `
            <div class="ai-issue-item ${issue.severity}">
                <span class="ai-issue-dot"></span>
                <span>${issue.text}</span>
            </div>
        `).join('');
    } else {
        issuesEl.innerHTML = `<p class="ai-no-issues">No critical issues found</p>`;
    }

    // Recommendations
    const recoEl = document.getElementById('aiRecommendations');
    if (data.recommendations && data.recommendations.length > 0) {
        recoEl.innerHTML = `<ol class="ai-reco-list">
            ${data.recommendations.map(r => `<li>${r}</li>`).join('')}
        </ol>`;
    } else {
        recoEl.innerHTML = `<p class="ai-no-issues">No recommendations at this time</p>`;
    }
}

// ============================================
// Map (Leaflet / OpenStreetMap)
// ============================================

function initMap(lat, lon) {
    const mapEl = document.getElementById('ipMap');
    if (!mapEl) return;
    
    if (mapInstance) {
        mapInstance.remove();
    }
    
    mapInstance = L.map('ipMap', {
        zoomControl: true,
        attributionControl: true
    }).setView([lat, lon], 10);
    
    // Use CartoDB dark tiles for the dark theme
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://carto.com/">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(mapInstance);
    
    // Custom marker
    const markerIcon = L.divIcon({
        className: 'custom-marker',
        html: `<div style="width:16px;height:16px;background:var(--red, #ef4444);border-radius:50%;border:3px solid white;box-shadow:0 0 10px rgba(239,68,68,0.5);"></div>`,
        iconSize: [16, 16],
        iconAnchor: [8, 8]
    });
    
    L.marker([lat, lon], { icon: markerIcon }).addTo(mapInstance);
}

// ============================================
// DNS Records Tab
// ============================================

function loadDNS(domain) {
    fetch(`/api/scan/dns/${domain}`)
        .then(r => r.json())
        .then(data => {
            dnsRecords = data.records;
            renderDNSTable(dnsRecords);
            document.getElementById('dnsCountText').textContent = `${data.total} records`;
        })
        .catch(err => {
            console.error('DNS error:', err);
            document.getElementById('dnsTableBody').innerHTML = `
                <tr><td colspan="5" class="loading-cell" style="color: var(--red);">
                    Failed to load DNS records
                </td></tr>`;
        });
}

function renderDNSTable(records) {
    const tbody = document.getElementById('dnsTableBody');
    
    if (records.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="loading-cell">No DNS records found</td></tr>`;
        return;
    }
    
    tbody.innerHTML = records.map(r => `
        <tr data-type="${r.type}">
            <td><span class="dns-type-badge type-${r.type}">${r.type}</span></td>
            <td class="dns-name">${r.name}</td>
            <td class="dns-value">${escapeHtml(r.value)}</td>
            <td class="dns-ttl">${formatTTL(r.ttl)}</td>
            <td><span class="dns-status">Active</span></td>
        </tr>
    `).join('');
}

function filterDNS(type) {
    document.querySelectorAll('.dns-filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === type);
    });
    
    if (type === 'ALL') {
        renderDNSTable(dnsRecords);
    } else {
        renderDNSTable(dnsRecords.filter(r => r.type === type));
    }
}

function searchDNS(query) {
    query = query.toLowerCase();
    const filtered = dnsRecords.filter(r => 
        r.name.toLowerCase().includes(query) || 
        r.value.toLowerCase().includes(query) ||
        r.type.toLowerCase().includes(query)
    );
    renderDNSTable(filtered);
}

function formatTTL(ttl) {
    return `${ttl}s`;
}

function exportCSV() {
    if (dnsRecords.length === 0) return;
    
    const headers = ['Type', 'Name', 'Value', 'TTL', 'Status'];
    const rows = dnsRecords.map(r => [r.type, r.name, `"${r.value}"`, r.ttl, r.status]);
    
    let csv = headers.join(',') + '\n';
    csv += rows.map(r => r.join(',')).join('\n');
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${currentDomain}_dns_records.csv`;
    a.click();
    URL.revokeObjectURL(url);
}

// ============================================
// Subdomains Tab
// ============================================

function loadSubdomains() {
    const tbody = document.getElementById('subdomainTableBody');
    const btn = document.getElementById('rescanSubdomains');
    
    btn.disabled = true;
    btn.innerHTML = `<div class="spinner" style="width:16px;height:16px;border-width:2px;margin:0;"></div> Scanning...`;
    
    tbody.innerHTML = `<tr><td colspan="5" class="loading-cell">
        <div class="spinner"></div>
        <span>Scanning subdomains... This may take a moment.</span>
    </td></tr>`;
    
    fetch(`/api/scan/subdomains/${currentDomain}`)
        .then(async (r) => {
            const data = await r.json().catch(() => ({}));
            if (!r.ok) {
                throw new Error(data.error || `Server error (${r.status})`);
            }
            return data;
        })
        .then(data => {
            if (!Array.isArray(data.subdomains)) {
                throw new Error('Invalid response from server');
            }
            subdomainResults = data.subdomains;
            document.getElementById('subTotalCount').textContent = data.total;
            const dnsOnly = data.dns_only || 0;
            const webTcp = data.active || 0;
            let activeLine;
            if (dnsOnly > 0 && webTcp > 0) {
                activeLine = `${webTcp} web/TCP · ${dnsOnly} DNS-only`;
            } else if (dnsOnly > 0) {
                activeLine = `${dnsOnly} DNS-only`;
            } else {
                activeLine = `${webTcp} web/TCP`;
            }
            document.getElementById('subActiveCount').textContent = activeLine;
            renderSubdomainTable(subdomainResults);
            
            btn.disabled = false;
            btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/>
                <line x1="8" y1="12" x2="16" y2="12"/>
            </svg> Scan Subdomains`;
        })
        .catch(err => {
            console.error('Subdomain error:', err);
            const msg = err.message ? escapeHtml(err.message) : 'Failed to scan subdomains';
            tbody.innerHTML = `<tr><td colspan="5" class="loading-cell" style="color: var(--red);">
                ${msg}
            </td></tr>`;
            btn.disabled = false;
            btn.innerHTML = `Retry Scan`;
        });
}

function subdomainHttpCell(s) {
    if (s.http_code) {
        const httpClass = getHTTPClass(s.http_code);
        return `<span class="http-badge ${httpClass}">${s.http_code}</span>`;
    }
    if (s.reachability === 'tcp') {
        return `<span class="subdomain-placeholder" title="Ports 80 or 443 accept TCP; no HTTP response during probe (firewall, timeout, or non-HTTP service)">TCP only</span>`;
    }
    return `<span class="subdomain-placeholder" title="DNS resolves but our HTTP/HTTPS requests did not get a response in time (still a valid hostname)">DNS only</span>`;
}

function subdomainLatencyCell(s) {
    if (s.response_time) {
        const barColor = getResponseBarColor(s.response_time);
        const barWidth = Math.min((s.response_time / 500) * 100, 100);
        return `
                <div class="response-time-cell">
                    <div class="response-bar-container">
                        <div class="response-bar" style="width: ${barWidth}%; background: ${barColor};"></div>
                    </div>
                    <span class="response-time-text">${s.response_time}ms</span>
                </div>`;
    }
    if (s.reachability === 'tcp') {
        return `<span class="subdomain-placeholder" title="No HTTP timing available">N/A</span>`;
    }
    return `<span class="subdomain-placeholder" title="No web response measured">N/A</span>`;
}

function renderSubdomainTable(subdomains) {
    const tbody = document.getElementById('subdomainTableBody');
    
    if (subdomains.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="loading-cell">No subdomains found</td></tr>`;
        return;
    }
    
    tbody.innerHTML = subdomains.map(s => {
        const openUrl = `https://${s.subdomain}`;
        const statusClass = s.status === 'Active' ? 'active' : 'dns-only';
        const statusLabel = s.status === 'DNS-Only' ? 'DNS only' : 'Active';
        
        return `
        <tr data-status="${s.status}">
            <td><a class="subdomain-link" href="${openUrl}" target="_blank" rel="noopener noreferrer">${s.subdomain}</a></td>
            <td><span class="subdomain-status ${statusClass}">${statusLabel}</span></td>
            <td>${subdomainHttpCell(s)}</td>
            <td>${subdomainLatencyCell(s)}</td>
            <td>
                <div class="action-btns">
                    <a class="action-btn" href="${openUrl}" target="_blank" rel="noopener noreferrer" title="Open">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                            <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
                        </svg>
                    </a>
                    <button class="action-btn" onclick="copyToClipboard(${JSON.stringify(s.subdomain)})" title="Copy">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                        </svg>
                    </button>
                </div>
            </td>
        </tr>`;
    }).join('');
}

function getHTTPClass(code) {
    if (!code) return '';
    if (code >= 200 && code < 300) return 'http-2xx';
    if (code >= 300 && code < 400) return 'http-3xx';
    if (code >= 400 && code < 500) return 'http-4xx';
    if (code >= 500) return 'http-5xx';
    return '';
}

function getResponseBarColor(ms) {
    if (!ms) return '#64748b';
    if (ms < 100) return '#22c55e';
    if (ms < 200) return '#84cc16';
    if (ms < 300) return '#f59e0b';
    return '#ef4444';
}

function toggleActiveOnly() {
    const activeOnly = document.getElementById('activeOnlyToggle').checked;
    if (activeOnly) {
        renderSubdomainTable(subdomainResults.filter(s => s.status === 'Active'));
    } else {
        renderSubdomainTable(subdomainResults);
    }
}

function searchSubdomains(query) {
    query = query.toLowerCase();
    const filtered = subdomainResults.filter(s => 
        s.subdomain.toLowerCase().includes(query)
    );
    renderSubdomainTable(filtered);
}

// ============================================
// Security Tab
// ============================================

function loadSecurity(domain, force = false) {
    return fetch(`/api/scan/security/${domain}${force ? '?force=true' : ''}`)
        .then(r => r.json())
        .then(data => {
            renderSecurityRisk(data);
            renderSecurityChecklist(data.checks);
            updateHeaderRiskScore(data);
        })
        .catch(err => {
            console.error('Security error:', err);
        });
}

function renderSecurityRisk(data) {
    const score = data.score;
    const circumference = 2 * Math.PI * 75;
    const offset = circumference - ((score / 100) * circumference);
    
    const circle = document.getElementById('securityRiskCircle');
    const scoreText = document.getElementById('securityScoreText');
    const riskLevel = document.getElementById('securityRiskLevel');
    const sublabel = document.getElementById('securitySublabel');
    const checkCount = document.getElementById('securityCheckCount');
    
    // Animate score
    setTimeout(() => {
        circle.style.strokeDashoffset = offset;
        circle.style.transition = 'stroke-dashoffset 1.5s ease';
        
        if (score >= 80) {
            circle.style.stroke = '#22c55e';
            riskLevel.style.color = '#22c55e';
        } else if (score >= 50) {
            circle.style.stroke = '#f59e0b';
            riskLevel.style.color = '#f59e0b';
        } else {
            circle.style.stroke = '#ef4444';
            riskLevel.style.color = '#ef4444';
        }
    }, 100);
    
    scoreText.textContent = score;
    riskLevel.textContent = data.risk_level;
    sublabel.textContent = `Based on ${data.total} security checks`;
    checkCount.textContent = `${data.passed}/${data.total} checks passed`;
    
    document.getElementById('secPassedCount').textContent = data.passed;
    document.getElementById('secFailedCount').textContent = data.failed;
    document.getElementById('secWarningCount').textContent = data.warnings;
}

function renderSecurityChecklist(checks) {
    const body = document.getElementById('securityChecklistBody');
    
    body.innerHTML = checks.map(check => {
        const iconSvg = getCheckStatusIcon(check.status);
        const badgeSvg = getCheckBadgeIcon(check.status);
        
        return `
        <div class="security-check-item ${check.status}">
            <div class="check-info">
                <div class="check-icon ${check.status}">
                    ${iconSvg}
                </div>
                <div class="check-text">
                    <h4>${check.name}</h4>
                    <p>${check.description}</p>
                </div>
            </div>
            <div class="check-badge ${check.status}">
                ${badgeSvg}
            </div>
        </div>`;
    }).join('');
}

function getCheckStatusIcon(status) {
    if (status === 'pass') {
        return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`;
    } else if (status === 'fail') {
        return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;
    } else {
        return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    }
}

function getCheckBadgeIcon(status) {
    if (status === 'pass') {
        return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`;
    } else if (status === 'fail') {
        return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>`;
    } else {
        return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>`;
    }
}

function updateHeaderRiskScore(data) {
    const gauge = document.getElementById('riskGauge');
    const circle = document.getElementById('riskCircle');
    const scoreText = document.getElementById('riskScoreText');
    const levelText = document.getElementById('riskLevel');
    const valText = document.getElementById('riskScoreVal');
    
    gauge.style.display = 'flex';
    
    const score = data.score;
    const circumference = 2 * Math.PI * 34;
    const offset = circumference - ((score / 100) * circumference);
    
    setTimeout(() => {
        circle.style.strokeDashoffset = offset;
        circle.style.transition = 'stroke-dashoffset 1.5s ease';
        
        const riskColor = score >= 80 ? '#22c55e' : score >= 50 ? '#f59e0b' : '#ef4444';
        circle.style.stroke = riskColor;
        levelText.style.color = riskColor;
        if (valText) valText.style.color = riskColor;
    }, 100);
    
    scoreText.textContent = score;
    if (valText) valText.textContent = score;
    levelText.textContent = data.risk_level;
}

// ============================================
// Threat Intel Tab
// ============================================

function loadThreatIntel(domain) {
    tabDataLoaded.threatintel = true;

    fetch(`/api/scan/threatintel/${domain}`)
        .then(r => r.json())
        .then(data => {
            renderThreatStatus(data);
            renderBlacklistChecks(data);
            renderReputationScore(data.reputation);
            renderThreatSummary(data.threat_summary);
        })
        .catch(err => {
            console.error('Threat Intel error:', err);
        });
}

function renderThreatStatus(data) {
    // Malware card
    const malwareCard = document.getElementById('threatMalwareCard');
    const mStatus = data.malware.status;
    malwareCard.innerHTML = `
        <div class="threat-status-icon ${mStatus}">
            ${mStatus === 'safe' ? 
                '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' :
                '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
            }
        </div>
        <h3>Malware Status</h3>
        <p>${data.malware.label}</p>
        <span class="threat-badge ${mStatus}">${data.malware.badge}</span>
    `;

    // Phishing card
    const phishingCard = document.getElementById('threatPhishingCard');
    const pStatus = data.phishing.status;
    phishingCard.innerHTML = `
        <div class="threat-status-icon ${pStatus}">
            ${pStatus === 'safe' ? 
                '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' :
                '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
            }
        </div>
        <h3>Phishing Risk</h3>
        <p>${data.phishing.label}</p>
        <span class="threat-badge ${pStatus}">${data.phishing.badge}</span>
    `;

    // Blacklist card
    const blCard = document.getElementById('threatBlacklistCard');
    const bStatus = data.blacklist.status;
    blCard.innerHTML = `
        <div class="threat-status-icon ${bStatus}">
            ${bStatus === 'safe' ? 
                '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' :
                '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
            }
        </div>
        <h3>Blacklist Status</h3>
        <p>${data.blacklist.label}</p>
        <span class="threat-badge ${bStatus}">${data.blacklist.badge}</span>
    `;
}

function renderBlacklistChecks(data) {
    const body = document.getElementById('blacklistChecklistBody');
    const subtitle = document.getElementById('blacklistSubtitle');
    const badges = document.getElementById('blacklistBadges');

    subtitle.textContent = `${data.clean_count} of ${data.blacklist_checks.length} registries clean`;
    badges.innerHTML = `
        <span class="bl-badge clean">${data.clean_count} Clean</span>
        ${data.flagged_count > 0 ? `<span class="bl-badge flagged">${data.flagged_count} Flagged</span>` : ''}
    `;

    body.innerHTML = data.blacklist_checks.map(check => `
        <div class="blacklist-check-item">
            <div class="bl-check-left">
                <span class="bl-service-icon">${check.icon}</span>
                <span class="bl-service-name">${check.name}</span>
            </div>
            <span class="bl-status ${check.status}">
                <span class="bl-status-dot"></span>
                ${check.status === 'clean' ? 'Clean' : 'Suspicious'}
            </span>
        </div>
    `).join('');
}

function renderReputationScore(reputation) {
    const scoreEl = document.getElementById('reputationScoreValue');
    const bar = document.getElementById('reputationBar');
    
    scoreEl.innerHTML = `<span class="rep-score-number">${reputation.score}</span><span class="rep-score-total">/100</span>`;
    
    setTimeout(() => {
        bar.style.width = `${reputation.score}%`;
        if (reputation.score >= 70) {
            bar.style.background = 'linear-gradient(90deg, #ef4444, #f59e0b, #22c55e)';
        } else if (reputation.score >= 40) {
            bar.style.background = 'linear-gradient(90deg, #ef4444, #f59e0b)';
        } else {
            bar.style.background = '#ef4444';
        }
    }, 200);
}

function renderThreatSummary(summary) {
    const body = document.getElementById('threatSummaryBody');
    
    body.innerHTML = `
        <div class="threat-intel-grid">
            <div class="ti-stat">
                <div class="ti-stat-icon">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                </div>
                <div class="ti-stat-label">Total Threats</div>
                <div class="ti-stat-value">${summary.total_threats}</div>
            </div>
            <div class="ti-stat">
                <div class="ti-stat-icon">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
                </div>
                <div class="ti-stat-label">Reported Abuse</div>
                <div class="ti-stat-value accent-red">${summary.reported_abuse}</div>
            </div>
            <div class="ti-stat">
                <div class="ti-stat-icon">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                </div>
                <div class="ti-stat-label">Spam Score</div>
                <div class="ti-stat-value">${summary.spam_score}</div>
            </div>
            <div class="ti-stat">
                <div class="ti-stat-icon">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>
                </div>
                <div class="ti-stat-label">Categories</div>
                <div class="ti-stat-value">${summary.categories_count}</div>
            </div>
        </div>
        ${summary.categories && summary.categories.length > 0 ? `
            <div class="ti-categories">
                <span class="ti-cat-label">Categories</span>
                <div class="ti-cat-tags">
                    ${summary.categories.map(c => `<span class="ti-cat-tag">${c}</span>`).join('')}
                </div>
            </div>
        ` : ''}
    `;
}

// ============================================
// Monitoring Tab
// ============================================

function loadMonitoring(domain) {
    tabDataLoaded.monitoring = true;

    fetch(`/api/scan/monitoring/${domain}`)
        .then(r => r.json())
        .then(data => {
            renderMonitoringStats(data.stats);
            renderWatchedDomains(data.watched_domains);
            renderResponseTime(data.response_time);
        })
        .catch(err => {
            console.error('Monitoring error:', err);
        });
}

function renderMonitoringStats(stats) {
    document.getElementById('monStatMonitored').textContent = stats.monitored;
    document.getElementById('monStatOnline').textContent = stats.online;
    document.getElementById('monStatOffline').textContent = stats.offline;
    document.getElementById('monStatDegraded').textContent = stats.degraded;
}

function renderWatchedDomains(domains) {
    const tbody = document.getElementById('watchedDomainsBody');
    const count = document.getElementById('watchedDomainsCount');
    
    count.textContent = `${domains.length} domains monitored`;

    tbody.innerHTML = domains.map(d => {
        const statusClass = d.status.toLowerCase();
        const rtColor = getResponseBarColor(d.response_time);
        
        return `
        <tr>
            <td>
                <div class="watched-domain-name">
                    <span class="wd-dot ${statusClass}"></span>
                    <a href="http://${d.domain}" target="_blank" class="subdomain-link">${d.domain}</a>
                </div>
            </td>
            <td><span class="subdomain-status ${statusClass === 'online' ? 'active' : statusClass === 'offline' ? 'inactive' : 'degraded-status'}">${d.status}</span></td>
            <td class="${getUptimeClass(d.uptime)}">${d.uptime}</td>
            <td><span class="ssl-days-badge">${d.ssl_days}</span></td>
            <td>${d.response_time ? `<span style="color: ${rtColor}; font-weight: 600;">${d.response_time}ms</span>` : '<span style="color: var(--text-muted)">N/A</span>'}</td>
            <td class="text-muted">${d.last_check}</td>
            <td>
                <button class="remove-wd-btn" onclick="removeWatchedDomain('${d.domain}')" title="Remove from watch list">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
                </button>
            </td>
        </tr>`;
    }).join('');
}

function getUptimeClass(uptime) {
    if (!uptime || uptime === 'N/A') return 'text-muted';
    const val = parseFloat(uptime);
    if (val >= 99) return 'uptime-good';
    if (val >= 95) return 'uptime-ok';
    return 'uptime-bad';
}

function renderResponseTime(data) {
    const domain = data.domain || '';
    document.getElementById('responseTimeDomain').textContent = `${domain} — Last 7 days`;

    // Draw chart
    const canvas = document.getElementById('responseTimeChart');
    const ctx = canvas.getContext('2d');
    
    // Set canvas resolution
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = 180 * dpr;
    canvas.style.width = rect.width + 'px';
    canvas.style.height = '180px';
    ctx.scale(dpr, dpr);
    
    const w = rect.width;
    const h = 180;
    const padding = { top: 20, right: 20, bottom: 30, left: 10 };
    const chartW = w - padding.left - padding.right;
    const chartH = h - padding.top - padding.bottom;
    
    const history = Array.isArray(data.history) ? data.history : [];
    ctx.clearRect(0, 0, w, h);

    if (history.length > 0) {
        const values = history.map(h => h.value);
        const maxVal = Math.max(1, ...values) * 1.2;
        const xSpan = Math.max(history.length - 1, 1);

        const gradient = ctx.createLinearGradient(0, padding.top, 0, h - padding.bottom);
        gradient.addColorStop(0, 'rgba(6, 182, 212, 0.3)');
        gradient.addColorStop(1, 'rgba(6, 182, 212, 0.0)');

        ctx.beginPath();
        history.forEach((point, i) => {
            const x = padding.left + (i / xSpan) * chartW;
            const y = padding.top + chartH - (point.value / maxVal) * chartH;
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.lineTo(padding.left + chartW, h - padding.bottom);
        ctx.lineTo(padding.left, h - padding.bottom);
        ctx.closePath();
        ctx.fillStyle = gradient;
        ctx.fill();

        ctx.beginPath();
        history.forEach((point, i) => {
            const x = padding.left + (i / xSpan) * chartW;
            const y = padding.top + chartH - (point.value / maxVal) * chartH;
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.strokeStyle = '#06b6d4';
        ctx.lineWidth = 2.5;
        ctx.lineJoin = 'round';
        ctx.stroke();

        history.forEach((point, i) => {
            const x = padding.left + (i / xSpan) * chartW;
            const y = padding.top + chartH - (point.value / maxVal) * chartH;
            ctx.beginPath();
            ctx.arc(x, y, 3, 0, Math.PI * 2);
            ctx.fillStyle = '#06b6d4';
            ctx.fill();
        });

        ctx.fillStyle = '#64748b';
        ctx.font = '11px Inter, sans-serif';
        ctx.textAlign = 'center';
        history.forEach((point, i) => {
            const x = padding.left + (i / xSpan) * chartW;
            ctx.fillText(point.day, x, h - 8);
        });
    } else {
        ctx.fillStyle = '#64748b';
        ctx.font = '12px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No response time history available', w / 2, h / 2);
    }

    // Stats
    const statsEl = document.getElementById('responseStats');
    statsEl.innerHTML = `
        <div class="response-stat-row">
            <span class="rs-label">Avg Response</span>
            <span class="rs-value accent-cyan">${data.avg_response}ms</span>
        </div>
        <div class="response-stat-row">
            <span class="rs-label">Uptime (7d)</span>
            <span class="rs-value accent-green">${data.uptime_7d}</span>
        </div>
        <div class="response-stat-row">
            <span class="rs-label">Incidents (7d)</span>
            <span class="rs-value accent-red">${data.incidents_7d}</span>
        </div>
    `;

    // Last 24h bar
    const last24h = document.getElementById('last24hSection');
    last24h.innerHTML = `
        <div class="last-24h-header">
            <span class="last-24h-title">Last 24 hours</span>
        </div>
        <div class="last-24h-bar">
            ${(data.last_24h || []).map(v => `<div class="h-bar-slot ${v ? 'up' : 'down'}"></div>`).join('')}
        </div>
        <div class="last-24h-labels">
            <span>24h ago</span>
            <span>Now</span>
        </div>
    `;
}

function refreshCurrentScan() {
    const btn = document.querySelector('.refresh-scan-btn');
    if (btn) btn.classList.add('spinning');
    
    // Clear cache state
    tabDataLoaded = {};
    
    // Perform forced re-scans for critical components
    Promise.all([
        loadOverview(currentDomain, true),
        loadSecurity(currentDomain, true),
        loadDNS(currentDomain),
        loadAIInsights(currentDomain)
    ]).finally(() => {
        setTimeout(() => {
            if (btn) btn.classList.remove('spinning');
        }, 1000);
    });
}

function addWatchedDomain() {
    const input = document.getElementById('addDomainInput');
    const domain = input.value.trim();
    if (!domain) return;

    // Call API to add domain
    fetch('/api/watched', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            input.value = '';
            // Reload monitoring data to show new domain
            loadMonitoring();
        } else {
            alert('Domain already in watch list or failed to add.');
        }
    })
    .catch(err => {
        console.error('Error adding watched domain:', err);
        alert('Error adding domain to watch list.');
    });
}


function removeWatchedDomain(domain) {
    if (!confirm(`Remove ${domain} from watch list?`)) return;

    fetch(`/api/watched/${domain}`, {
        method: 'DELETE'
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            loadMonitoring();
        }
    })
    .catch(err => console.error('Error removing domain:', err));
}

// ============================================
// History Tab
// ============================================

function loadHistory(domain) {
    fetch(`/api/scan/history/${domain}`)
        .then(r => r.json())
        .then(data => {
            document.getElementById('historyCount').textContent = `${data.total} events recorded`;
            renderTimeline(data.events);
        })
        .catch(err => {
            console.error('History error:', err);
        });
}

function renderTimeline(events) {
    const timeline = document.getElementById('historyTimeline');
    
    if (events.length === 0) {
        timeline.innerHTML = `<p style="text-align: center; color: var(--text-muted); padding: 40px;">No history events found</p>`;
        return;
    }
    
    timeline.innerHTML = events.map(event => {
        const iconSvg = getTimelineIcon(event.type);
        
        return `
        <div class="timeline-item">
            <div class="timeline-icon ${event.type}">
                ${iconSvg}
            </div>
            <div class="timeline-content">
                <div class="timeline-title">
                    <h4>${event.title}</h4>
                    <span class="timeline-tag ${event.type}">${event.type}</span>
                </div>
                <div class="timeline-date">${event.date}</div>
                ${event.description ? `<div class="timeline-desc">${event.description}</div>` : ''}
            </div>
        </div>`;
    }).join('');
}

function getTimelineIcon(type) {
    switch (type) {
        case 'registration':
            return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>`;
        case 'ssl':
            return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
        case 'renewal':
            return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>`;
        case 'dns':
            return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/></svg>`;
        case 'expiry':
            return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`;
        default:
            return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>`;
    }
}

// ============================================
// Tech Stack Tab
// ============================================



// Utility Functions
// ============================================

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Brief visual feedback could be added here
    }).catch(err => {
        // Fallback
        const el = document.createElement('textarea');
        el.value = text;
        document.body.appendChild(el);
        el.select();
        document.execCommand('copy');
        document.body.removeChild(el);
    });
}

// ============================================
// Compare Modal
// ============================================

function openCompareModal() {
    const overlay = document.getElementById('compareModalOverlay');
    overlay.classList.add('active');
    document.body.style.overflow = 'hidden';
    setTimeout(() => {
        document.getElementById('compareDomainInput').focus();
    }, 200);
}

function closeCompareModal(event) {
    if (event && event.target !== event.currentTarget) return;
    const overlay = document.getElementById('compareModalOverlay');
    overlay.classList.remove('active');
    document.body.style.overflow = '';
}

function runComparison() {
    const input = document.getElementById('compareDomainInput');
    const compareDomain = input.value.trim();
    if (!compareDomain) {
        input.focus();
        return;
    }

    const results = document.getElementById('compareResults');
    const loading = document.getElementById('compareLoading');

    results.style.display = 'none';
    loading.style.display = 'flex';

    fetch(`/api/compare/${currentDomain}/${compareDomain}`)
        .then(r => r.json())
        .then(data => {
            loading.style.display = 'none';
            results.style.display = 'block';
            renderComparisonResults(data);
        })
        .catch(err => {
            console.error('Compare error:', err);
            loading.style.display = 'none';
            results.style.display = 'block';
            document.getElementById('compareTable').innerHTML = `
                <p style="color: var(--red); text-align: center; padding: 20px;">Failed to compare domains. Please check the domain name and try again.</p>`;
        });
}

function renderComparisonResults(data) {
    const d1 = data.domain1;
    const d2 = data.domain2;

    // Domain tabs
    const tabs = document.getElementById('compareDomainTabs');
    tabs.innerHTML = `
        <span class="cmp-domain-tab domain1-tab">${d1.domain}</span>
        <span class="cmp-domain-tab domain2-tab">${d2.domain}</span>
    `;

    // Build comparison table
    const table = document.getElementById('compareTable');

    // Risk Score Row with gauges
    const gauge1 = buildMiniGauge(d1.score, d1.risk_level);
    const gauge2 = buildMiniGauge(d2.score, d2.risk_level);

    // Domain age bar helper
    function ageBar(age, color) {
        return `<span class="cmp-age-bar" style="background: ${color};">${age}</span>`;
    }

    // Open ports display
    function portDisplay(count) {
        const color = count === 0 ? 'var(--green)' : 'var(--orange)';
        return `<span class="cmp-port-badge" style="background: ${count === 0 ? 'var(--green-dim)' : 'var(--orange-dim)'}; color: ${color};">${count} open</span>`;
    }

    // SSL days badge
    function sslDaysBadge(days) {
        const color = days > 90 ? 'var(--green)' : days > 30 ? 'var(--orange)' : 'var(--red)';
        const bg = days > 90 ? 'var(--green-dim)' : days > 30 ? 'var(--orange-dim)' : 'var(--red-dim)';
        return `<span class="cmp-port-badge" style="background: ${bg}; color: ${color};">${days}d</span>`;
    }

    const rows = [
        { label: 'Risk Score', v1: gauge1, v2: gauge2, isHtml: true },
        { label: 'Status', v1: d1.status, v2: d2.status },
        { label: 'Domain Age', v1: ageBar(d1.domain_age, '#22c55e'), v2: ageBar(d2.domain_age, '#06b6d4'), isHtml: true },
        { label: 'Registrar', v1: d1.registrar, v2: d2.registrar },
        { label: 'Expires', v1: d1.expires, v2: d2.expires },
        { label: 'IP Address', v1: d1.ip_address, v2: d2.ip_address },
        { label: 'Hosting', v1: d1.hosting, v2: d2.hosting },
        { label: 'SSL Status', v1: d1.ssl_status, v2: d2.ssl_status },
        { label: 'SSL Days Left', v1: sslDaysBadge(d1.ssl_days), v2: sslDaysBadge(d2.ssl_days), isHtml: true },
        { label: 'SSL Issuer', v1: d1.ssl_issuer, v2: d2.ssl_issuer },
        { label: 'Open Ports', v1: portDisplay(d1.open_ports), v2: portDisplay(d2.open_ports), isHtml: true }
    ];

    table.innerHTML = rows.map(row => `
        <div class="cmp-row">
            <div class="cmp-label">${row.label}</div>
            <div class="cmp-val cmp-val-1">${row.isHtml ? row.v1 : escapeHtml(row.v1 || 'N/A')}</div>
            <div class="cmp-val cmp-val-2">${row.isHtml ? row.v2 : escapeHtml(row.v2 || 'N/A')}</div>
        </div>
    `).join('');
}

function buildMiniGauge(score, riskLevel) {
    let color = '#22c55e';
    if (score < 50) color = '#ef4444';
    else if (score < 80) color = '#f59e0b';

    const circumference = 2 * Math.PI * 24;
    const offset = circumference - ((score / 100) * circumference);

    return `
        <div class="cmp-gauge-wrapper">
            <svg width="56" height="56" viewBox="0 0 56 56">
                <circle cx="28" cy="28" r="24" fill="none" stroke="#1e293b" stroke-width="4"/>
                <circle cx="28" cy="28" r="24" fill="none" stroke="${color}" stroke-width="4"
                        stroke-linecap="round"
                        stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
                        transform="rotate(-90 28 28)"/>
                <text x="28" y="26" text-anchor="middle" class="cmp-gauge-score" fill="white">${score}</text>
                <text x="28" y="36" text-anchor="middle" class="cmp-gauge-max" fill="#64748b">/100</text>
            </svg>
            <span class="cmp-risk-label" style="color: ${color};">${riskLevel}</span>
        </div>`;
}

// ============================================
// Export Modal
// ============================================

let currentExportFormat = 'pdf';

function openExportModal() {
    const overlay = document.getElementById('exportModalOverlay');
    overlay.classList.add('active');
    document.body.style.overflow = 'hidden';
    updateExportCount();
    setupExportCheckboxListeners();
}

function closeExportModal(event) {
    if (event && event.target !== event.currentTarget) return;
    const overlay = document.getElementById('exportModalOverlay');
    overlay.classList.remove('active');
    document.body.style.overflow = '';
}

function setExportFormat(format) {
    currentExportFormat = format;
    document.getElementById('formatPDF').classList.toggle('active', format === 'pdf');
    document.getElementById('formatCSV').classList.toggle('active', format === 'csv');
    updateExportButtonLabel();
}

function setupExportCheckboxListeners() {
    const checkboxes = document.querySelectorAll('.export-checkbox');
    checkboxes.forEach(cb => {
        cb.onchange = function() {
            const item = this.closest('.export-section-item');
            if (this.checked) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
            updateExportCount();
        };
    });
}

function selectAllSections(event) {
    event.preventDefault();
    document.querySelectorAll('.export-checkbox').forEach(cb => {
        cb.checked = true;
        cb.closest('.export-section-item').classList.add('active');
    });
    updateExportCount();
}

function selectNoSections(event) {
    event.preventDefault();
    document.querySelectorAll('.export-checkbox').forEach(cb => {
        cb.checked = false;
        cb.closest('.export-section-item').classList.remove('active');
    });
    updateExportCount();
}

function updateExportCount() {
    const checked = document.querySelectorAll('.export-checkbox:checked').length;
    document.getElementById('exportSectionCount').textContent = checked;
    updateExportButtonLabel();
}

function updateExportButtonLabel() {
    const count = document.querySelectorAll('.export-checkbox:checked').length;
    const formatLabel = currentExportFormat.toUpperCase();
    const btn = document.getElementById('exportDownloadBtn');
    btn.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        Download ${formatLabel} (${count} sections)`;
}

function downloadExport() {
    const checked = document.querySelectorAll('.export-checkbox:checked');
    if (checked.length === 0) {
        alert('Please select at least one section to export.');
        return;
    }

    const sections = Array.from(checked).map(cb => cb.dataset.section);

    if (currentExportFormat === 'csv') {
        downloadCSVExport(sections);
    } else {
        downloadPDFExport(sections);
    }
}

function downloadCSVExport(sections) {
    let csv = `DomainXray Report - ${currentDomain}\n`;
    csv += `Generated: ${new Date().toLocaleString()}\n\n`;

    // Domain Overview
    if (sections.includes('overview')) {
        csv += `=== DOMAIN OVERVIEW ===\n`;
        const domainInfo = document.getElementById('domainInfoBody');
        if (domainInfo) {
            const rows = domainInfo.querySelectorAll('.info-row');
            rows.forEach(row => {
                const label = row.querySelector('.info-label')?.textContent?.trim() || '';
                const value = row.querySelector('.info-value')?.textContent?.trim() || '';
                csv += `${label},${value}\n`;
            });
        }
        csv += `\n`;
    }

    // DNS Records
    if (sections.includes('dns') && dnsRecords.length > 0) {
        csv += `=== DNS RECORDS ===\n`;
        csv += `Type,Name,Value,TTL\n`;
        dnsRecords.forEach(r => {
            csv += `${r.type},"${r.name}","${r.value}",${r.ttl}\n`;
        });
        csv += `\n`;
    }

    // Subdomains
    if (sections.includes('subdomains') && subdomainResults.length > 0) {
        csv += `=== SUBDOMAINS ===\n`;
        csv += `Subdomain,Status,HTTP Code,Response Time\n`;
        subdomainResults.forEach(s => {
            csv += `${s.subdomain},${s.status},${s.http_code || 'N/A'},${s.response_time || 'N/A'}ms\n`;
        });
        csv += `\n`;
    }

    // Security
    if (sections.includes('security')) {
        csv += `=== SECURITY ANALYSIS ===\n`;
        const checkItems = document.querySelectorAll('.security-check-item');
        checkItems.forEach(item => {
            const name = item.querySelector('.check-text h4')?.textContent?.trim() || '';
            const desc = item.querySelector('.check-text p')?.textContent?.trim() || '';
            const status = item.classList.contains('pass') ? 'PASS' : item.classList.contains('fail') ? 'FAIL' : 'WARNING';
            csv += `${status},${name},${desc}\n`;
        });
        csv += `\n`;
    }



    // Download
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${currentDomain}_report.csv`;
    a.click();
    URL.revokeObjectURL(url);

    closeExportModal();
}

function downloadPDFExport(sections) {
    fetch('/api/export/pdf', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            domain: currentDomain,
            sections: sections
        }),
    })
    .then(response => {
        if (!response.ok) throw new Error('PDF generation failed');
        return response.blob();
    })
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${currentDomain}_Security_Report.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        closeExportModal();
    })
    .catch(error => {
        console.error('Export Error:', error);
        alert('Failed to generate PDF report. Please try again.');
    });
}

// Close modals on Escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        const compareOverlay = document.getElementById('compareModalOverlay');
        const exportOverlay = document.getElementById('exportModalOverlay');
        if (compareOverlay && compareOverlay.classList.contains('active')) closeCompareModal();
        if (exportOverlay && exportOverlay.classList.contains('active')) closeExportModal();
    }
});

// ============================================
// Tool Execution logic
// ============================================

let currentToolType = null;

function launchTool(type, title, desc, color) {
    currentToolType = type;
    const panel = document.getElementById('toolExecutionPanel');
    const input = document.getElementById('toolInput');
    const titleEl = document.getElementById('toolExecTitle');
    const descEl = document.getElementById('toolExecDesc');
    const iconEl = document.getElementById('toolExecIcon');
    const resultEl = document.getElementById('toolResult');
    const loadingEl = document.getElementById('toolLoading');

    // Reset panel
    resultEl.style.display = 'none';
    loadingEl.style.display = 'none';
    input.value = '';
    
    // Set content
    titleEl.textContent = title;
    descEl.textContent = desc;
    panel.style.setProperty('--tool-accent', color);
    
    // Set placeholder and specific defaults
    if (type === 'reverse_ip') {
        input.placeholder = 'Enter IP address (e.g. 93.184.216.34)';
        if (!input.value && typeof currentIP !== 'undefined' && currentIP) input.value = currentIP;
    } else if (type === 'email_lookup') {
        input.placeholder = 'Enter domain (e.g. example.com)';
        input.value = currentDomain;
    } else if (type === 'username_checker') {
        input.placeholder = 'Enter username to check...';
    } else if (type === 'whois_lookup') {
        input.placeholder = 'Enter domain...';
        input.value = currentDomain;
    } else if (type === 'port_scanner') {
        input.placeholder = 'Enter target (IP or domain)...';
        if (typeof currentIP !== 'undefined' && currentIP) input.value = currentIP;
    } else if (type === 'http_headers') {
        input.placeholder = 'Enter URL...';
        input.value = `https://${currentDomain}`;
    }

    // Set Icon
    iconEl.innerHTML = getToolIconMarkup(type);

    // Show panel
    panel.style.display = 'block';
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    input.focus();
}

function closeToolPanel() {
    const panel = document.getElementById('toolExecutionPanel');
    panel.style.display = 'none';
    currentToolType = null;
}

function runTool() {
    const input = document.getElementById('toolInput').value.trim();
    if (!input) return;

    const resultEl = document.getElementById('toolResult');
    const loadingEl = document.getElementById('toolLoading');
    const outputEl = document.getElementById('toolOutput');

    resultEl.style.display = 'none';
    loadingEl.style.display = 'flex';

    // Call REAL backend tool APIs
    let url = "";
    if (currentToolType === 'whois_lookup') url = `/api/tool/whois/${input}`;
    else if (currentToolType === 'port_scanner') url = `/api/tool/ports/${input}`;
    else if (currentToolType === 'http_headers') {
        const targetUrl = input.startsWith('http') ? input : `https://${input}`;
        url = `/api/tool/headers?url=${encodeURIComponent(targetUrl)}`;
    }
    else if (currentToolType === 'username_checker') url = `/api/tool/usernames/${encodeURIComponent(input)}`;
    else if (currentToolType === 'reverse_ip') url = `/api/tool/reverse_ip/${input}`;
    else if (currentToolType === 'email_lookup') url = `/api/tool/emails/${input}`;

    fetch(url)
        .then(r => {
            if (!r.ok) throw new Error('Tool execution failed');
            return r.json();
        })
        .then(data => {
            loadingEl.style.display = 'none';
            resultEl.style.display = 'block';
            outputEl.textContent = data.output || "No data returned.";
        })
        .catch(err => {
            console.error('Tool Error:', err);
            loadingEl.style.display = 'none';
            resultEl.style.display = 'block';
            outputEl.textContent = `Error: ${err.message}. Please check your input (domain or IP).`;
        });
}

function copyToolResult() {
    const output = document.getElementById('toolOutput').textContent;
    copyToClipboard(output);
    const btn = document.querySelector('.copy-result-btn');
    const originalText = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = originalText, 2000);
}

function getToolIconMarkup(type) {
    const icons = {
        'email_lookup': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>`,
        'reverse_ip': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>`,
        'username_checker': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
        'whois_lookup': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
        'port_scanner': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`,
        'http_headers': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`
    };
    return icons[type] || '';
}

// Initialize theme on script load
initTheme();
function loadMailForensics(domain) {
    fetch(`/api/scan/security/${domain}`)
        .then(r => r.json())
        .then(data => {
            renderMailSecurity(data);
            tabDataLoaded.mail = true;
        })
        .catch(err => {
            console.error('Mail forensics error:', err);
        });
}

function renderMailSecurity(data) {
    const container = document.getElementById('mailForensicsContent');
    const spf = data.checks.find(c => c.name === 'SPF Record') || {};
    const dmarc = data.checks.find(c => c.name === 'DMARC Policy') || {};

    let html = `
        <div class="mail-forensics-container" style="padding: 2rem; display: flex; flex-direction: column; gap: 2rem;">
            <div class="mail-header-cards" style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1.5rem;">
                <div class="info-card" style="padding: 1.5rem; border: 1px solid var(--border); border-radius: var(--radius-lg); background: var(--bg-card);">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
                        <div class="card-icon" style="--accent: var(--green);">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                        </div>
                        <h3>SPF Authenticity</h3>
                    </div>
                    <div class="mail-status-badge ${spf.status || 'fail'}">${spf.status === 'pass' ? 'Strong' : 'Weak/Missing'}</div>
                    <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 10px;">SPF (Sender Policy Framework) prevents domain spoofing.</p>
                </div>
                <div class="info-card" style="padding: 1.5rem; border: 1px solid var(--border); border-radius: var(--radius-lg); background: var(--bg-card);">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
                        <div class="card-icon" style="--accent: var(--cyan);">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                        </div>
                        <h3>DMARC Enforcement</h3>
                    </div>
                    <div class="mail-status-badge ${dmarc.status || 'fail'}">${dmarc.status === 'pass' ? 'Enforced' : 'Unprotected'}</div>
                    <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 10px;">DMARC provides instructions to mail servers on how to handle SPF/DKIM failures.</p>
                </div>
            </div>

            <div class="ssl-detail-section">
                <div class="ssl-section-title">Forensic Record Breakdown</div>
                <div class="mail-record-box">
                    <div class="mail-record-label">Raw SPF Record</div>
                    <code class="mail-record-value">${escapeHtml(spf.raw || 'No SPF record found')}</code>
                </div>
                <div class="mail-record-box" style="margin-top: 1.5rem;">
                    <div class="mail-record-label">Raw DMARC Record</div>
                    <code class="mail-record-value">${escapeHtml(dmarc.raw || 'No DMARC record found')}</code>
                </div>
            </div>

            <div class="ssl-detail-section" style="border-color: var(--border-light); background: rgba(var(--cyan-rgb), 0.03);">
                <div class="ssl-section-title" style="color: var(--cyan);">Mail Security Advisory</div>
                <p style="font-size: 0.9rem; line-height: 1.6;">
                    ${dmarc.status === 'pass' ? 
                        `This domain is protected by a strong DMARC policy. Unauthorized emails claiming to be from this domain will be rejected or quarantined by most global mail servers.` : 
                        `<strong>Critical Warning:</strong> This domain lacks strong DMARC enforcement. It is susceptible to "Exact-Domain Spoofing," meaning attackers can send emails that appear to originate from this domain's executive leadership or support teams.`}
                </p>
            </div>
        </div>
    `;
    container.innerHTML = html;
}

function renderHeadingAnalysis(domain) {
    const selector = document.getElementById('headingAnalysisContainer');
    if (!selector) return;

    selector.innerHTML = `
        <div class="info-card" style="margin-top: 2rem;">
            <div class="card-header">
                <div class="card-title-group">
                    <div class="card-icon" style="--accent: var(--cyan);">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/></svg>
                    </div>
                    <div>
                        <h3>Site Identity Forensics</h3>
                        <span class="card-subtitle">Public HTML title &amp; meta from the live homepage</span>
                    </div>
                </div>
            </div>
            <div class="card-body">
                <div id="headingForensicsResult">
                    <p class="identity-forensics-hint">
                        Fetches the site homepage over HTTPS (then HTTP) and reads the <code>&lt;title&gt;</code> and description meta tags.
                    </p>
                    <div class="identity-forensics-actions">
                        <button type="button" class="scan-btn sm-btn" id="identityAuditBtn">Begin Identity Audit</button>
                    </div>
                </div>
            </div>
        </div>
    `;
    const btn = document.getElementById('identityAuditBtn');
    if (btn) {
        btn.addEventListener('click', () => performIdentityCrawl(domain));
    }
}

function performIdentityCrawl(domain) {
    const resultDiv = document.getElementById('headingForensicsResult');
    if (!resultDiv) return;

    resultDiv.innerHTML = `<div class="info-skeleton" style="padding: 1rem;"><div class="skeleton-line"></div><div class="skeleton-line"></div><div class="skeleton-line"></div></div>`;

    const safeDomain = encodeURIComponent(domain);
    fetch(`/api/scan/site-identity/${safeDomain}`)
        .then((r) => r.json())
        .then((data) => {
            const titleText = data.title
                ? data.title
                : '(No title tag found in HTML)';
            const metaText = data.meta_description
                ? data.meta_description
                : (data.ok ? 'No meta description / og:description found on the homepage.' : (data.error || 'Could not load the page.'));

            const titleHtml = escapeHtml(titleText);
            const metaHtml = escapeHtml(metaText);
            const urlLine = data.final_url
                ? `<div class="identity-forensics-url">${escapeHtml(data.final_url)}</div>`
                : '';

            const statusLine = data.ok
                ? `HTTP ${data.http_status ?? '—'} · Homepage fetched successfully.`
                : escapeHtml(data.error || 'Request failed');

            resultDiv.innerHTML = `
            <div class="forensic-heading-grid">
                <div class="heading-item forensic-block">
                    <span class="forensic-label">Page title</span>
                    <div class="forensic-value">${titleHtml}</div>
                    ${urlLine}
                </div>
                <div class="heading-item forensic-block">
                    <span class="forensic-label">Meta summary</span>
                    <div class="forensic-value forensic-meta">${metaHtml}</div>
                </div>
                <div class="heading-item forensic-block">
                    <span class="forensic-label">Fetch status</span>
                    <div class="forensic-value">${data.ok ? escapeHtml(statusLine) : `<span class="identity-forensics-warn">${statusLine}</span>`}</div>
                </div>
            </div>
            <div class="identity-forensics-actions">
                <button type="button" class="scan-btn sm-btn" id="identityAuditBtnRetry">Run again</button>
            </div>`;

            const retry = document.getElementById('identityAuditBtnRetry');
            if (retry) {
                retry.addEventListener('click', () => performIdentityCrawl(domain));
            }
        })
        .catch((err) => {
            console.error('Identity audit error:', err);
            resultDiv.innerHTML = `
                <p class="identity-forensics-error">${escapeHtml(err.message || 'Request failed')}</p>
                <div class="identity-forensics-actions">
                    <button type="button" class="scan-btn sm-btn" id="identityAuditBtnRetry">Retry</button>
                </div>`;
            const retry = document.getElementById('identityAuditBtnRetry');
            if (retry) retry.addEventListener('click', () => performIdentityCrawl(domain));
        });
}

function toggleAccordion(header) {
    const accordion = header.parentElement;
    accordion.classList.toggle('collapsed');
}


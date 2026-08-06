# Wazuh Version Compatibility Guide

## Overview

This document details the compatibility of Wazuh MCP Server with different Wazuh versions, including supported features, API changes, and version-specific considerations.

---

## ✅ **Supported Versions**

| Wazuh Version | Support Status | Recommendation | Notes |
|---------------|----------------|----------------|-------|
| **4.14.7** | ✅ **Fully Supported** | **RECOMMENDED** | Latest stable release (Jul 2026) |
| **4.14.6** | ✅ **Fully Supported** | Recommended | Stable release (Jul 2026) |
| **4.14.5** | ✅ **Fully Supported** | Recommended | Stable release (Apr 2026) |
| **4.14.4** | ✅ **Fully Supported** | Recommended | Stable release (Mar 2026) |
| **4.14.3** | ✅ **Fully Supported** | Recommended | Stable release |
| **4.14.2** | ✅ **Fully Supported** | Recommended | Stable release |
| **4.14.1** | ✅ **Fully Supported** | Recommended | Previous stable release |
| **4.14.0** | ✅ **Fully Supported** | Recommended | Stable release |
| **4.13.x** | ✅ **Fully Supported** | Recommended | All 4.13 releases supported |
| **4.12.x** | ✅ **Fully Supported** | Recommended | Includes CTI enhancements |
| **4.11.x** | ✅ **Fully Supported** | Recommended | Stable release series |
| **4.10.x** | ✅ **Fully Supported** | Recommended | Stable release series |
| **4.9.x** | ✅ **Fully Supported** | Supported | Stable release series |
| **4.8.x** | ✅ **Fully Supported** | Minimum Recommended | First version with Indexer API |
| **4.0.0 - 4.7.x** | ⚠️ **Limited Support** | Not Recommended | Legacy versions, limited features |
| **< 4.0.0** | ❌ **Not Supported** | Not Compatible | Use newer Wazuh version |

---

## 🎯 **Version-Specific Features**

### **Wazuh 4.14.7 (Latest - July 2026)**

**Changes:**
- ✅ Removed deprecated `wazuh-dbd` daemon and `database_output` configuration (not used by this server)
- ✅ Improved API authentication stability (bounded thread pools, regex timeouts, payload size limits)
- ✅ Improved cluster payload buffer allocation and archive decompression limits
- ✅ Updated Python dependencies (aiohttp, cryptography, PyJWT, python-multipart, starlette)

**API Compatibility:** ✅ No breaking changes — Manager REST API and Indexer contracts unchanged

**MCP Server Support:** Fully compatible — no code changes required

### **Wazuh 4.14.6 (July 2026)**

**Changes:**
- ✅ RBAC enforcement for agent removal/group-edit/upgrade moved to the API level
- ✅ `update-user` endpoint admin protection fixed
- ✅ Input validation hardening in cluster and authentication paths

**API Compatibility:** ✅ No breaking changes. Note: agent write operations are now RBAC-enforced server-side — ensure your API user has the required permissions for active response and agent management tools

**MCP Server Support:** Fully compatible — no code changes required

### **Wazuh 4.14.5 (April 2026)**

**Changes:**
- ✅ `/events` endpoint rate-limiting bypass fixed
- ✅ Nested JSON depth limit in API request processing
- ✅ Upload size limit configuration mismatch resolved
- ✅ Security fixes (cluster memory allocation, DAPI RBAC bypass, Authd path traversal, Remoted heap overflow)

**API Compatibility:** ✅ No breaking changes

**MCP Server Support:** Fully compatible — no code changes required

### **Wazuh 4.14.4 (March 2026)**

**Bug Fixes:**
- ✅ Fixed timestamps in `/agents/upgrade_result` endpoint to return proper UTC time
- ✅ Resolved API login race condition
- ✅ Improved cluster file synchronization path handling
- ✅ Unified date formats in Active Response logs (now consistent `YYYY/MM/DD HH:MM:SS`)
- ✅ Fixed Windows OS edition detection and Windows 11 detection post-upgrade
- ✅ Resolved macOS crash during Syscollector reload
- ✅ Fixed heap-based null write buffer underflows

**API Compatibility:** ✅ No breaking changes from 4.14.x series

**MCP Server Support:** Fully compatible — no code changes required

### **Wazuh 4.14.3**

**Enhancements:**
- ✅ All 4.14.x improvements included
- ✅ Enhanced stability and bug fixes
- ✅ Performance optimizations for large-scale deployments

**API Compatibility:** ✅ No breaking changes from 4.14.x series

**MCP Server Support:** Fully tested and verified

### **Wazuh 4.14.1**

**Features:**
- ✅ IAM role support for VPC flow logs in AWS wodle
- ✅ Static and temporary AWS credentials support in Amazon Security Lake
- ✅ Enhanced wazuh-db startup performance
- ✅ Improved vulnerability index upgrades with hash-based validation
- ✅ Structured logging for indexer connector errors
- ✅ Homebrew 2.0+ support in macOS IT Hygiene module

**Bug Fixes:**
- Fixed indefinite waiting in FIM whodata health checks
- Resolved manager vulnerability scanning trigger failures
- Corrected IndexerConnector data loss issues
- Fixed Windows Registry key recognition for non-UTF-8 keys

**API Compatibility:** ✅ No breaking changes from 4.13.x

**MCP Server Support:** Fully tested and verified

### **Wazuh 4.13.x**

**Features:**
- Enhanced security monitoring capabilities
- Improved agent management
- Better vulnerability detection

**API Compatibility:** ✅ Compatible with all MCP server endpoints

### **Wazuh 4.12.x**

**Key Features:**
- ✅ **Cyber Threat Intelligence (CTI)** data integration
- ✅ **Package condition fields** in vulnerability data
- ✅ Enhanced CVE tracking and analysis
- ✅ Improved vulnerability correlation

**New Endpoints:**
- `/vulnerability/cti/{cve_id}` - Get CTI data for specific CVEs
- Enhanced `/vulnerability/agents` response with CTI references

**MCP Server Support:**
- `get_cti_data()` - Fetch CTI information for CVEs
- `get_vulnerability_details()` - Enhanced vulnerability data

### **Wazuh 4.11.x**

**Features:**
- Improved cluster management
- Enhanced log analysis
- Better active response capabilities

**API Compatibility:** ✅ Fully compatible

### **Wazuh 4.10.x**

**Features:**
- Enhanced syscollector data collection
- Improved FIM (File Integrity Monitoring)
- Better SCA (Security Configuration Assessment)

**API Compatibility:** ✅ Fully compatible

### **Wazuh 4.9.x**

**Features:**
- Security enhancements
- Performance improvements
- Better agent connectivity

**API Compatibility:** ✅ Fully compatible

### **Wazuh 4.8.x (Minimum Recommended)**

**Major Changes:**
- ✅ **Wazuh Indexer API** introduced (replaces Elasticsearch)
- ✅ **Centralized vulnerability detection**
- ⚠️ **Breaking Change:** `/vulnerability` endpoint removed
- ⚠️ **Breaking Change:** `custom` parameter removed from active response
- ✅ New `/vulnerability/agents` endpoint
- ✅ `/manager/version/check` endpoint added

**Migration from 4.7.x:**
- Update to use `/vulnerability/agents` instead of `/vulnerability`
- Remove `custom` parameter from active response calls
- Enable Wazuh Indexer for better performance

### **Wazuh 4.0.0 - 4.7.x (Limited Support)**

**Limitations:**
- ❌ No Wazuh Indexer support — **alert and vulnerability tools will not work**
- ⚠️ Only agent management, system monitoring, and active response tools are functional
- ⚠️ Uses deprecated `/vulnerability` endpoint (not supported by this MCP server)
- ⚠️ Older API structure

**Recommendation:** Upgrade to 4.8.0 or higher for full functionality

---

## 🔧 **Configuration by Version**

### **For Wazuh 4.8.0 - 4.14.7 (Recommended)**

```bash
# .env configuration
WAZUH_HOST=your-wazuh-server
WAZUH_PORT=55000
WAZUH_USER=your-user
WAZUH_PASS=your-password
WAZUH_VERIFY_SSL=true

# Configure the Indexer (required for alerts, aggregation, and vulnerabilities on 4.8.0+).
# Setting WAZUH_INDEXER_HOST is what enables the Indexer-backed tools.
WAZUH_INDEXER_HOST=your-indexer-host
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=admin
```

### **For Wazuh 4.0.0 - 4.7.x (Legacy)**

```bash
# .env configuration
WAZUH_HOST=your-wazuh-server
WAZUH_PORT=55000
WAZUH_USER=your-user
WAZUH_PASS=your-password
WAZUH_VERIFY_SSL=true

# Leave WAZUH_INDEXER_HOST unset: the Indexer-backed tools (alert search,
# get_alerts_aggregated, vulnerabilities) require Wazuh 4.8.0+ and won't work here.
```

---

## 📊 **API Endpoint Compatibility Matrix**

| Endpoint | 4.8-4.14.7 | 4.0-4.7.x | Notes |
|----------|------------|-----------|-------|
| `/agents` | ✅ | ✅ | Fully compatible across all versions |
| `/alerts` (via Indexer) | ✅ | ❌ | Requires Wazuh Indexer (4.8.0+) |
| `/vulnerability/agents` | ✅ | ❌ | Added in 4.8.0 |
| `/vulnerability` | ❌ | ⚠️ | Removed in 4.8.0, deprecated in 4.7.0 |
| `/vulnerability/cti/{cve}` | ✅ | ❌ | Added in 4.12.0 |
| `/cluster/status` | ✅ | ✅ | Fully compatible |
| `/manager/stats` | ✅ | ✅ | Fully compatible |
| `/manager/version/check` | ✅ | ❌ | Added in 4.8.0 |
| `/active-response` | ✅ | ⚠️ | `custom` param removed in 4.8.0 |
| `/rules` | ✅ | ✅ | Fully compatible |
| `/decoders` | ✅ | ✅ | Fully compatible |
| `/syscheck` (FIM) | ✅ | ✅ | Fully compatible |
| `/syscollector` | ✅ | ✅ | Fully compatible |

---

## 🚀 **Feature Availability**

### **Available in 4.8.0+**
- ✅ Wazuh Indexer integration
- ✅ Centralized vulnerability detection
- ✅ Enhanced agent statistics
- ✅ Improved cluster management
- ✅ Version checking capabilities

### **Available in 4.12.0+**
- ✅ Cyber Threat Intelligence (CTI) data
- ✅ Package condition tracking
- ✅ Enhanced CVE correlation
- ✅ Advanced vulnerability analytics

### **Available in 4.14.0+**
- ✅ AWS IAM role support
- ✅ Amazon Security Lake integration
- ✅ Enhanced vulnerability indexing
- ✅ Improved error logging

---

## ⚠️ **Breaking Changes History**

### **4.8.0 Breaking Changes**
1. **Vulnerability Endpoint Removed**
   - Old: `GET /vulnerability`
   - New: `GET /vulnerability/agents`
   - Impact: MCP Server automatically uses correct endpoint

2. **Active Response Parameter**
   - Removed: `custom` parameter
   - Impact: MCP Server filters this parameter automatically

### **No Breaking Changes in 4.9.0 - 4.14.7**
- All API endpoints remain compatible
- New features are additive only
- Backward compatibility maintained

---

## 🔍 **Version Detection**

The MCP Server automatically detects your Wazuh version and adapts:

```python
# Example: Version-aware vulnerability fetching
async def get_vulnerabilities(self, **params):
    # Automatically uses /vulnerability/agents for 4.8.0+
    # Falls back to legacy endpoint for 4.7.x and below
    return await self._request("GET", "/vulnerability/agents", params=params)
```

---

## 📝 **Upgrade Path**

### **From 4.0.x - 4.7.x to 4.8.0+**

1. **Backup your current Wazuh configuration**
2. **Upgrade Wazuh server to 4.8.0 or higher**
3. **Install Wazuh Indexer**
4. **Update MCP Server configuration** (setting the Indexer host enables the Indexer-backed tools):
   ```bash
   WAZUH_INDEXER_HOST=your-indexer
   WAZUH_INDEXER_PORT=9200
   WAZUH_INDEXER_USER=admin
   WAZUH_INDEXER_PASS=admin
   ```
5. **Restart MCP Server** - No code changes needed!

### **From 4.8.x - 4.13.x to 4.14.x**

- ✅ **Direct upgrade** - No configuration changes needed
- ✅ **Automatic compatibility** - MCP Server works immediately
- ✅ **New features available** - AWS integrations and enhancements

---

## ✅ **Testing & Verification**

### **Verify Compatibility**

```bash
# Check Wazuh version
curl -k -u user:password https://wazuh-server:55000/

# Test MCP Server health
curl http://localhost:3000/health

# Expected response includes:
{
  "services": {
    "wazuh": "healthy",
    "mcp": "healthy"
  }
}
```

### **Test Specific Features**

**For 4.14.x:**
```bash
# Test vulnerability detection
curl -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_wazuh_vulnerabilities"},"id":"1"}'
```

**For 4.12.0+:**
```bash
# Test CTI data
curl -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_cti_data","arguments":{"cve_id":"CVE-2024-1234"}},"id":"1"}'
```

---

## 📚 **Additional Resources**

- **Wazuh Release Notes**: https://documentation.wazuh.com/current/release-notes/
- **Wazuh API Documentation**: https://documentation.wazuh.com/current/user-manual/api/
- **Wazuh Upgrade Guide**: https://documentation.wazuh.com/current/upgrade-guide/
- **MCP Server Documentation**: README.md

---

## 🎯 **Recommendation Summary**

**For Production Use:**
- ✅ **Use Wazuh 4.14.x** (latest stable)
- ✅ **Minimum: Wazuh 4.8.0** (for full features)
- ✅ **Enable Wazuh Indexer** (required for 4.8.0+)
- ✅ **Keep both updated** (Wazuh + MCP Server)

**Compatibility Guarantee:**
This MCP Server is **fully tested and verified** with Wazuh versions 4.8.0 through 4.14.7, with ongoing support for future 4.x releases.

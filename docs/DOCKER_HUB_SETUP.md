# Docker Hub Auto-Publishing Setup

This document explains how to configure automatic Docker image publishing to Docker Hub for the Wazuh MCP Server project.

## 🏭 Repository Configuration

### Docker Hub Repository
- **Organization**: `gensecaihq`
- **Repository**: `wazuh-mcp-server`
- **Full Image Name**: `gensecaihq/wazuh-mcp-server`
- **Visibility**: Public
- **URL**: https://hub.docker.com/r/gensecaihq/wazuh-mcp-server

## 🔐 Required GitHub Secrets

To enable automatic publishing, configure the following secrets in your GitHub repository:

### 1. Docker Hub Authentication Secrets

Navigate to: `GitHub Repository → Settings → Secrets and variables → Actions`

Add these repository secrets:

| Secret Name | Description | How to Get |
|-------------|-------------|------------|
| `DOCKERHUB_USERNAME` | Docker Hub username | Your Docker Hub username (e.g., `gensecaihq`) |
| `DOCKERHUB_TOKEN` | Docker Hub Access Token | Generate from Docker Hub Settings → Security |

### 2. Optional Notification Secrets

| Secret Name | Description | Required |
|-------------|-------------|----------|
| `SLACK_WEBHOOK_URL` | Slack webhook for notifications | No |
| `SNYK_TOKEN` | Snyk token for security scanning | No |

## 🎯 Creating Docker Hub Access Token

1. **Login to Docker Hub**
   - Go to https://hub.docker.com/
   - Sign in with your account

2. **Navigate to Security Settings**
   - Click your profile → Account Settings
   - Go to Security tab
   - Click "New Access Token"

3. **Create Access Token**
   - **Access Token Description**: `GitHub Actions - Wazuh MCP Server`
   - **Access permissions**: `Read, Write, Delete`
   - Click "Generate"

4. **Copy Token**
   - ⚠️ **Important**: Copy the token immediately - it won't be shown again
   - Store it securely in GitHub Secrets as `DOCKERHUB_TOKEN`

## 🚀 Trigger Conditions

The Docker publishing workflow automatically triggers on:

### 1. Version Tags (Recommended)
```bash
# Create and push a v3.x.x tag
git tag v3.0.0
git push origin v3.0.0
```

### 2. GitHub Releases
- When you publish a release on GitHub
- The release tag should follow `v3.x.x` pattern

### 3. Manual Workflow Dispatch
- Go to Actions → Docker Build and Publish
- Click "Run workflow"
- Specify version tag and push options

## 📋 Published Tags

When a v3.x.x release is published, the following tags are created:

| Tag Pattern | Example | Description |
|-------------|---------|-------------|
| `vX.Y.Z` | `v3.0.0` | Exact version |
| `vX.Y` | `v3.0` | Minor version |
| `vX` | `v3` | Major version |
| `v3-latest` | `v3-latest` | Latest v3.x version |
| `latest` | `latest` | Latest stable (main branch) |

## 🔒 Security Features

### Image Scanning
- **Trivy**: Vulnerability scanning
- **Snyk**: Security analysis
- **SBOM**: Software Bill of Materials generation

### Build Security
- Multi-platform builds (linux/amd64, linux/arm64)
- Non-root user execution
- Read-only filesystem
- Minimal attack surface

## 🛠️ Repository Setup Commands

### 1. Create Docker Hub Repository
```bash
# Using Docker Hub CLI (if available)
docker hub repo create gensecaihq/wazuh-mcp-server --description "Model Context Protocol server for Wazuh security platform"
```

### 2. Set Repository to Public
- Login to Docker Hub web interface
- Navigate to Repository Settings
- Set Visibility to "Public"

### 3. Configure GitHub Secrets
```bash
# Using GitHub CLI
gh secret set DOCKERHUB_USERNAME --body "gensecaihq"
gh secret set DOCKERHUB_TOKEN --body "your_access_token_here"

# Optional secrets
gh secret set SLACK_WEBHOOK_URL --body "https://hooks.slack.com/services/..."
gh secret set SNYK_TOKEN --body "your_snyk_token_here"
```

## 🧪 Testing the Setup

### 1. Test Manual Trigger
1. Go to GitHub Actions
2. Select "Docker Build and Publish"
3. Click "Run workflow"
4. Set:
   - **Tag**: `v3.0.0-test`
   - **Push to registry**: `true`
5. Monitor the workflow execution

### 2. Test Tag-Based Trigger
```bash
# Create a test tag
git tag v3.0.0-test
git push origin v3.0.0-test

# Check GitHub Actions for automatic trigger
```

### 3. Verify Image Published
```bash
# Pull the published image
docker pull gensecaihq/wazuh-mcp-server:v3.0.0-test

# Test the image
docker run --rm gensecaihq/wazuh-mcp-server:v3.0.0-test --version
```

## 📊 Monitoring & Maintenance

### View Build Logs
- Go to GitHub Actions
- Select the "Docker Build and Publish" workflow
- Check job logs for any issues

### Docker Hub Analytics
- Login to Docker Hub
- View repository analytics for pull statistics
- Monitor download trends

### Security Scanning Results
- Check GitHub Security tab for vulnerability reports
- Review Trivy and Snyk scan results
- Monitor SBOM artifacts

## 🚨 Troubleshooting

### Common Issues

1. **Authentication Failed**
   ```
   Error: denied: requested access to the resource is denied
   ```
   - **Solution**: Verify `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets
   - Check token permissions (Read, Write, Delete required)

2. **Repository Not Found**
   ```
   Error: repository does not exist or may require 'docker login'
   ```
   - **Solution**: Ensure repository `gensecaihq/wazuh-mcp-server` exists on Docker Hub
   - Verify repository name in workflow configuration

3. **Build Platform Issues**
   ```
   Error: failed to solve: failed to read dockerfile
   ```
   - **Solution**: Check Dockerfile exists and is valid
   - Verify build context and platform specifications

4. **Rate Limiting**
   ```
   Error: toomanyrequests: Too Many Requests
   ```
   - **Solution**: Wait and retry, or upgrade to Docker Hub Pro

### Debug Steps

1. **Check Secrets Configuration**
   ```bash
   # Verify secrets are set (don't show values)
   gh secret list
   ```

2. **Test Docker Hub Connection**
   ```bash
   # Test login locally
   echo "$DOCKERHUB_TOKEN" | docker login --username "$DOCKERHUB_USERNAME" --password-stdin
   ```

3. **Validate Workflow Syntax**
   ```bash
   # Use GitHub CLI to validate workflow
   gh workflow view "Docker Build and Publish"
   ```

## 📞 Support

- **GitHub Issues**: [Report problems](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Docker Hub Support**: [Docker Hub Help](https://hub.docker.com/support/)
- **Documentation**: [GitHub Actions Docs](https://docs.github.com/en/actions)

---

✅ **Status**: Ready for v3.0.0+ automatic publishing to https://hub.docker.com/r/gensecaihq/wazuh-mcp-server
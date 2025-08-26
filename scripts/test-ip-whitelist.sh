#!/bin/bash

# IP Whitelist Testing Script
# This script demonstrates how to test the IP whitelist functionality

set -e

echo "🔒 IP Whitelist Testing Script"
echo "================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SERVER_URL="http://localhost:8080"
HEALTH_ENDPOINT="${SERVER_URL}/health"

echo -e "${BLUE}Testing IP whitelist functionality...${NC}"
echo

# Function to test endpoint
test_endpoint() {
    local description="$1"
    local expected_status="$2"
    local headers="$3"
    
    echo -e "${YELLOW}Testing: $description${NC}"
    
    if [ -n "$headers" ]; then
        response=$(curl -s -o /dev/null -w "%{http_code}" $headers "$HEALTH_ENDPOINT" || echo "000")
    else
        response=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_ENDPOINT" || echo "000")
    fi
    
    if [ "$response" = "$expected_status" ]; then
        echo -e "${GREEN}✓ Expected status $expected_status, got $response${NC}"
    else
        echo -e "${RED}✗ Expected status $expected_status, got $response${NC}"
    fi
    echo
}

# Check if server is running
echo -e "${BLUE}1. Checking if server is running...${NC}"
if curl -s "$HEALTH_ENDPOINT" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Server is running at $SERVER_URL${NC}"
else
    echo -e "${RED}✗ Server is not running. Please start the server first.${NC}"
    echo "Run: make run or docker-compose up"
    exit 1
fi
echo

# Test scenarios
echo -e "${BLUE}2. Testing different IP scenarios...${NC}"

# Test with localhost IP (should work if localhost is whitelisted)
test_endpoint "Direct request (no custom headers)" "200"

# Test with X-Real-IP header simulating allowed IP
test_endpoint "X-Real-IP: 127.0.0.1 (localhost)" "200" "-H 'X-Real-IP: 127.0.0.1'"

# Test with X-Real-IP header simulating blocked IP (if whitelist is enabled)
test_endpoint "X-Real-IP: 203.0.113.1 (test IP)" "403" "-H 'X-Real-IP: 203.0.113.1'"

# Test with X-Forwarded-For header
test_endpoint "X-Forwarded-For: 127.0.0.1" "200" "-H 'X-Forwarded-For: 127.0.0.1, 192.168.1.1'"

# Test with blocked IP in X-Forwarded-For
test_endpoint "X-Forwarded-For: 203.0.113.2" "403" "-H 'X-Forwarded-For: 203.0.113.2, 192.168.1.1'"

echo -e "${BLUE}3. Testing API endpoints...${NC}"

# Test signup endpoint
echo -e "${YELLOW}Testing: Signup endpoint with blocked IP${NC}"
signup_response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "X-Real-IP: 203.0.113.3" \
    -d '{"email":"test@example.com","password":"TestPass123!","first_name":"Test","last_name":"User"}' \
    "${SERVER_URL}/api/v1/auth/signup" || echo "000")

if [ "$signup_response" = "403" ]; then
    echo -e "${GREEN}✓ Signup correctly blocked for unauthorized IP${NC}"
else
    echo -e "${YELLOW}ℹ Got status $signup_response (whitelist might be disabled)${NC}"
fi
echo

echo -e "${BLUE}4. Configuration Examples${NC}"
echo "================================"

cat << 'EOF'
To enable IP whitelisting, add to your .env file:

# Enable IP whitelisting
IP_WHITELIST_ENABLED=true

# Example configurations:

# Allow only localhost
ALLOWED_IPS=127.0.0.1,::1

# Allow office network
ALLOWED_IPS=192.168.1.0/24,10.0.0.0/8

# Allow specific IPs and ranges
ALLOWED_IPS=192.168.1.100,203.0.113.5,10.0.0.0/24,2001:db8::/32

# Disable whitelisting (allow all IPs)
IP_WHITELIST_ENABLED=false
ALLOWED_IPs=
EOF

echo
echo -e "${BLUE}5. Security Recommendations${NC}"
echo "================================"

cat << 'EOF'
Production Security Tips:

1. 🔐 Always test IP whitelist rules in staging first
2. 📝 Document all whitelisted IPs and their purposes  
3. 🔍 Monitor logs for blocked legitimate traffic
4. 🚨 Keep emergency access IPs whitelisted
5. 🏗️  Include load balancer and proxy IPs
6. 🔄 Regularly review and update IP lists
7. 📊 Set up alerts for repeated blocked attempts
8. 🔒 Use CIDR ranges instead of individual IPs when possible

Common Gotchas:
- Don't forget IPv6 addresses if you support them
- Consider dynamic IPs for mobile users
- Test with your actual deployment infrastructure
- Remember that proxies/CDNs may change source IPs
EOF

echo
echo -e "${GREEN}IP Whitelist testing complete! 🎉${NC}"
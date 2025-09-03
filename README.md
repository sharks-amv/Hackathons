# 🏥 Healthcare Management System - Backend API

A secure, enterprise-grade healthcare management system backend built with Spring Boot, implementing comprehensive OWASP Top 10 security measures and HIPAA compliance standards.

## 🔒 Security Features

### OWASP Top 10 Protection
- **A01: Broken Access Control** - Role-based access control (RBAC) with granular permissions
- **A02: Cryptographic Failures** - Argon2 password hashing, JWT tokens, SSL/TLS encryption
- **A03: Injection** - Input sanitization, parameterized queries, XSS protection
- **A04: Insecure Design** - Secure-by-design architecture with defense in depth
- **A05: Security Misconfiguration** - Comprehensive security headers, secure defaults
- **A06: Vulnerable Components** - Regular dependency scanning, rate limiting
- **A07: Authentication Failures** - Strong password policies, account lockout, JWT validation
- **A08: Software Integrity Failures** - Secure build pipeline, dependency verification
- **A09: Security Logging** - Comprehensive audit trails, security event monitoring
- **A10: Server-Side Request Forgery** - Input validation, allowlist approach

### Additional Security Measures
- 🔐 **SSL/TLS Encryption** - End-to-end encryption with HTTPS
- 🛡️ **Rate Limiting** - DDoS protection with configurable limits
- 📊 **Audit Logging** - Complete audit trails for compliance
- 🔍 **Input Sanitization** - XSS and injection prevention
- 🚫 **CORS Protection** - Configurable cross-origin policies
- 🔑 **JWT Authentication** - Secure token-based authentication
- 👥 **Multi-Role Support** - Patient, Doctor, Nurse, Admin, Staff roles

## 🏗️ Architecture

### Technology Stack
- **Framework**: Spring Boot 3.2.0
- **Security**: Spring Security 6.x
- **Database**: PostgreSQL 15+
- **Cache**: Redis (optional)
- **Authentication**: JWT (JSON Web Tokens)
- **Password Hashing**: Argon2
- **Build Tool**: Maven 3.8+
- **Java Version**: 17+

### Project Structure
```
healthcare-backend/
├── src/main/java/com/hospital/
│   ├── config/              # Configuration classes
│   ├── controller/          # REST controllers
│   ├── dto/                 # Data transfer objects
│   ├── entity/              # JPA entities
│   ├── enums/               # Enumerations
│   ├── exception/           # Custom exceptions
│   ├── repository/          # Data access layer
│   ├── security/            # Security components
│   └── service/             # Business logic
├── src/main/resources/
│   ├── application*.yml     # Configuration files
│   ├── db/migration/        # Database migration scripts
│   └── keystore.p12         # SSL certificate
├── docker-compose.yml       # Container orchestration
├── Dockerfile              # Container definition
└── pom.xml                 # Maven dependencies
```

## 🚀 Quick Start

### Prerequisites
- ☕ **Java 17+** (OpenJDK recommended)
- 🐘 **PostgreSQL 14+**
- 🛠️ **Maven 3.8+**
- 🐳 **Docker & Docker Compose**

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/healthcare-backend.git
   cd healthcare-backend
   ```

2. **Generate SSL keystore**
   ```bash
   chmod +x generate-keystore.sh
   ./generate-keystore.sh
   ```

3. **Start infrastructure services**
   ```bash
   docker-compose up -d postgres redis
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Run the application**
   ```bash
   chmod +x startup.sh
   ./startup.sh dev
   ```

### Alternative: Manual Setup

```bash
# Build the application
mvn clean package -DskipTests

# Set environment variables
export DB_PASSWORD=your_secure_password
export JWT_SECRET=your_jwt_secret_key

# Run the application
java -Dspring.profiles.active=dev -jar target/healthcare-backend-*.jar
```

## 📖 API Documentation

### Base URL
```
https://localhost:8443/api/v1
```

### Authentication Endpoints

#### Register New User
```http
POST /auth/register
Content-Type: application/json

{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePassword123!",
  "firstName": "John",
  "lastName": "Doe",
  "phoneNumber": "+1-555-0123",
  "dateOfBirth": "1990-01-01"
}
```

#### Login
```http
POST /auth/login
Content-Type: application/json

{
  "username": "johndoe",
  "password": "SecurePassword123!"
}
```

#### Refresh Token
```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "your_refresh_token_here"
}
```

### User Management Endpoints

#### Get Current User Profile
```http
GET /users/profile
Authorization: Bearer {access_token}
```

#### Update Profile
```http
PUT /users/profile
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Smith",
  "phoneNumber": "+1-555-0124"
}
```

#### Get All Users (Admin only)
```http
GET /users?page=0&size=20&role=PATIENT&search=john
Authorization: Bearer {admin_access_token}
```

#### Update User Status (Admin only)
```http
PATCH /users/{userId}/status
Authorization: Bearer {admin_access_token}
Content-Type: application/json

{
  "enabled": false,
  "reason": "Account suspended for review"
}
```

#### Change Password
```http
POST /users/change-password
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "currentPassword": "CurrentPassword123!",
  "newPassword": "NewSecurePassword123!",
  "confirmPassword": "NewSecurePassword123!"
}
```

### Health Check
```http
GET /health
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DB_HOST` | Database host | localhost | Yes |
| `DB_PORT` | Database port | 5432 | Yes |
| `DB_NAME` | Database name | healthcare_db | Yes |
| `DB_USERNAME` | Database username | healthcare_user | Yes |
| `DB_PASSWORD` | Database password | - | Yes |
| `JWT_SECRET` | JWT signing secret | - | Yes |
| `CORS_ALLOWED_ORIGINS` | Allowed CORS origins | - | Yes |
| `SSL_KEYSTORE_PASSWORD` | SSL keystore password | - | Yes |

### Application Profiles

#### Development (`dev`)
- Detailed logging enabled
- H2 console available
- Less strict security for easier development
- Shorter JWT expiration times

#### Production (`prod`)
- Minimal logging
- Strict security settings
- Long JWT expiration times
- Performance optimizations enabled

### Database Configuration

The application uses PostgreSQL with the following features:
- Connection pooling with HikariCP
- SSL encryption required
- Prepared statement caching
- Transaction isolation
- Read-only replica support

## 🔒 Security Configuration

### Password Policy
- Minimum 12 characters (14 in production)
- Must contain uppercase, lowercase, numbers, and special characters
- Password history tracking
- 90-day expiration (configurable)

### JWT Configuration
- 15-minute access token lifetime
- 24-hour refresh token lifetime
- HS256 signing algorithm
- Secure secret key required

### Rate Limiting
- 100 requests per minute (development)
- 60 requests per minute (production)
- IP-based and user-based limiting
- Configurable burst capacity

### Audit Logging
- All user actions logged
- Security events tracked
- HIPAA-compliant retention (7 years)
- Tamper-evident log storage

## 🏥 User Roles & Permissions

### Role Hierarchy
1. **ADMIN** - Full system access
   - User management
   - System configuration
   - All patient/medical data access
   - Audit log access

2. **DOCTOR** - Medical staff access
   - Patient data access
   - Medical record management
   - Appointment scheduling

3. **NURSE** - Nursing staff access
   - Patient care data
   - Basic medical records
   - Care plan management

4. **STAFF** - General healthcare staff
   - Limited patient data
   - Scheduling and administration

5. **PATIENT** - Patient portal access
   - Personal medical records
   - Appointment scheduling
   - Communication with providers

## 🐳 Docker Deployment

### Development
```bash
docker-compose up -d
```

### Production
```bash
docker-compose -f docker-compose.prod.yml up -d
```

### Container Health Checks
- Application: `https://localhost:8443/api/v1/health`
- PostgreSQL: Automatic health checks
- Redis: Automatic health checks

## 📊 Monitoring & Observability

### Health Endpoints
- `/actuator/health` - Application health
- `/actuator/metrics` - Application metrics
- `/actuator/info` - Application information

### Logging
- Structured JSON logging
- Configurable log levels
- Log rotation and retention
- Audit trail separation

### Metrics
- JVM metrics
- Database connection metrics
- HTTP request metrics
- Custom business metrics

## 🧪 Testing

### Run Tests
```bash
# Unit tests
mvn test

# Integration tests
mvn verify

# Security tests
mvn verify -Psecurity-tests
```

### Test Coverage
- Unit test coverage > 80%
- Integration test coverage for all endpoints
- Security test coverage for OWASP Top 10

## 🔍 Security Scanning

### Dependency Scanning
```bash
mvn org.owasp:dependency-check-maven:check
```

### Static Code Analysis
```bash
mvn sonar:sonar
```

### Container Scanning
```bash
docker scan healthcare-backend:latest
```

## 📈 Performance

### Optimization Features
- Database connection pooling
- JPA query optimization
- Response caching
- Gzip compression
- Async processing for audit logs

### Benchmarks
- Response time < 200ms (95th percentile)
- Throughput > 1000 RPS
- Memory usage < 512MB baseline
- Database connections < 20 active

## 🚨 Incident Response

### Security Incident Handling
1. **Detection** - Automated security event monitoring
2. **Response** - Immediate account lockout and alerting
3. **Investigation** - Comprehensive audit trail analysis
4. **Recovery** - Secure system restoration procedures
5. **Post-Incident** - Security posture improvement

### Monitoring Alerts
- Failed login attempts > 5
- Admin actions outside business hours
- Unusual data access patterns
- System performance degradation

## 🤝 Contributing

### Development Guidelines
1. Follow secure coding practices
2. Add security tests for new features
3. Update documentation
4. Run security scans before committing
5. Use feature branches and pull requests

### Code Standards
- Java coding standards (Google Style)
- Security-first development approach
- Comprehensive error handling
- Proper input validation
- Complete audit logging

## 📋 Compliance

### Standards Adherence
- **HIPAA** - Health Insurance Portability and Accountability Act
- **OWASP** - Open Web Application Security Project guidelines
- **ISO 27001** - Information security management
- **SOC 2** - Service Organization Control 2

### Data Protection
- End-to-end encryption
- Data anonymization capabilities
- Right to deletion (GDPR compliance)
- Audit trail integrity
- Secure data backup and recovery

## 📞 Support

### Documentation
- [API Documentation](https://docs.yourdomain.com/api)
- [Security Guide](https://docs.yourdomain.com/security)
- [Deployment Guide](https://docs.yourdomain.com/deployment)

### Contact
- **Security Issues**: security@yourdomain.com
- **General Support**: support@yourdomain.com
- **Documentation**: docs@yourdomain.com

### Community
- [GitHub Issues](https://github.com/yourusername/healthcare-backend/issues)
- [Discussions](https://github.com/yourusername/healthcare-backend/discussions)
- [Wiki](https://github.com/yourusername/healthcare-backend/wiki)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security Disclaimer

This is a healthcare management system handling sensitive patient data. Always:
- Use strong, unique passwords in production
- Enable all security features
- Regularly update dependencies
- Monitor security advisories
- Conduct regular security assessments
- Follow your organization's security policies

## 🔄 Changelog

### Version 1.0.0 (Current)
- ✅ Complete OWASP Top 10 protection
- ✅ Multi-role authentication system
- ✅ Comprehensive audit logging
- ✅ SSL/TLS encryption
- ✅ Rate limiting and DDoS protection
- ✅ Input sanitization and validation
- ✅ Docker containerization
- ✅ Production-ready configuration

---

**🏥 Built with ❤️ for secure healthcare management**

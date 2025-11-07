# 🚀 Orbis

**NextGen Asset Management Platform**

Orbis is a modern, enterprise-grade asset management platform designed to provide comprehensive visibility and control over your IT infrastructure. Built with performance, security, and extensibility in mind.

---

## ✨ Features

### 🔧 Core Platform
- **Cross-Platform Server** - High-performance Rust backend that runs on Windows, Linux, and macOS
- **React GUI** - Modern, intuitive web interface for seamless asset management
- **Mobile Friendly** - Responsive design that works perfectly on tablets and smartphones
- **JSON API** - RESTful API for easy integration with existing tools and workflows

### 🤖 Intelligent Agents
- **Cross-Platform Agents** - Deploy on Windows and Linux hosts to automatically gather system information
- **Auto-Discovery** - Detect installed software, hardware specs, and system configurations
- **Real-Time Sync** - Automatic synchronization of asset data with the backend
- **Auto-Update** - Agents update themselves automatically, no manual intervention required

### ⚙️ Automation & Integration
- **Cron Jobs** - Schedule automated tasks and maintenance operations
- **Automation Workflows** - Build complex workflows with conditional logic and triggers
- **Plugin System** - Extend functionality with custom plugins using a powerful hook-based architecture
- **AI Integrations** - Leverage artificial intelligence for predictive maintenance and insights

### 🔔 Notifications
- **Telegram Integration** - Receive alerts and notifications via Telegram
- **Slack Integration** - Keep your team informed with Slack notifications
- **Multi-Channel Support** - Configure different notification channels for different events

### 🔐 Security & Compliance
- **Multi-Factor Authentication (MFA)** - Enhanced security with 2FA support
- **Role-Based Access Control (RBAC)** - Granular permissions and user management
- **End-to-End Encryption (E2E)** - Secure data transmission and storage
- **Audit Logging** - Track all system changes and access

### 📊 Customization
- **Customizable Dashboards** - Create personalized views tailored to your needs
- **Flexible Reporting** - Generate custom reports and export data
- **Theming Support** - Adapt the interface to match your brand

### 🔄 Maintenance
- **Server Auto-Update** - Server updates itself automatically with zero downtime
- **Agent Auto-Update** - Keep all deployed agents up-to-date effortlessly

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│           Orbis Assets Platform             │
├─────────────────────────────────────────────┤
│  React GUI (Web & Mobile)                   │
├─────────────────────────────────────────────┤
│  Rust Server (Cross-Platform)               │
│  • JSON API                                 │
│  • Plugin System                            │
│  • Automation Engine                        │
│  • Notification Service                     │
├─────────────────────────────────────────────┤
│  Agents (Windows/Linux)                     │
│  • Asset Discovery                          │
│  • Real-Time Sync                           │
│  • Auto-Update                              │
└─────────────────────────────────────────────┘
```

---

## 🚀 Getting Started

### Prerequisites
- Rust 1.91 (nightly)+ (for server compilation)
- Node.js 18+ (for GUI)
- Docker (optional, for containerized deployment)

### Quick Start

#### 1. Clone the Repository
```bash
git clone https://github.com/ebalo55/Orbis.git
cd orbis
```

#### 2. Build the Server
```bash
cargo build --release
```

#### 3. Run the Server
```bash
./target/release/orbis
```

#### 4. Access the Web Interface
Open your browser and navigate to:
```
http://localhost:8080
```

---

## 📦 Installation

### Server Installation

#### Linux
```bash
# Download the latest release
wget https://github.com/ebalo55/Orbis/releases/latest/download/orbis-assets-linux-amd64

# Make it executable
chmod +x orbis-linux-amd64

# Run the server
./orbis-linux-amd64
```

#### Windows
```powershell
# Download and run the installer
# Or use the portable executable
orbis-windows-amd64.exe
```

### Agent Installation

#### Linux
```bash
curl -sSL https://install.orbis-assets.io/agent.sh | sudo bash
```

#### Windows
```powershell
Invoke-WebRequest -Uri https://install.orbis-assets.io/agent.ps1 -UseBasicParsing | Invoke-Expression
```

---

## 📚 Documentation

- **[Plugin System Guide](plugins/API/README.md)** - Complete documentation

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🌟 Support

- **Documentation**: [https://docs.orbis-assets.io](https://docs.orbis-assets.io)
- **Issues**: [GitHub Issues](https://github.com/yourusername/orbis-assets/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/orbis-assets/discussions)
- **Email**: me@ebalo.xyz

---

## 🙏 Acknowledgments

Built with ❤️ using:
- [Rust](https://www.rust-lang.org/) - Systems programming language
- [React](https://react.dev/) - UI library
- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [Tokio](https://tokio.rs/) - Async runtime

---

<div align="center">

**[Website](https://ebalo.xyz)** • **[Documentation](#)**

Made with 🚀 by the Ebalo

</div>


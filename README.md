# LLM-based Penetration Testing Framework

An intelligent penetration testing framework based on the Kill Chain model, powered by Large Language Models (LLMs). This framework automates the entire penetration testing process from reconnaissance to objective completion.

## Features

- **Automated Kill Chain Execution**: Follows the complete cyber kill chain model (Reconnaissance → Weaponization → Delivery → Exploitation → Installation → Command & Control → Actions on Objectives)
- **LLM-Powered Planning**: Uses master LLM to generate and adjust execution plans intelligently
- **Multi-Agent Architecture**: Specialized agents for each kill chain stage
- **Real-time Monitoring**: Live TUI interface with Textual for real-time task tracking
- **Smart Interruption**: Pause and replan during execution with user input
- **Distributed Execution**: Built on Ray for scalable distributed task execution
- **Bilingual Support**: Supports both English and Chinese (configurable)

## Requirements

- Python 3.8+
- LLM API access (OpenAI-compatible API)
- Network access for penetration testing tools

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd LLM-based-Penetration-Testing
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure LLM settings in `configs/llm_runtime.json`:
```json
{
  "master_agent": {
    "protocol": "https",
    "host": "api.example.com",
    "port": 443,
    "api_key": "your-api-key",
    "model_name": "gpt-4",
    "temperature": 0.7,
    "max_tokens": 4096
  },
  "ui": {
    "language": "en"
  }
}
```

## Configuration

### Language Settings

The framework supports bilingual display (English/Chinese). Configure the language in `configs/llm_runtime.json`:

```json
{
  "ui": {
    "language": "en"  // or "zh" for Chinese
  }
}
```

Default language is English (`"en"`).

## Usage

### Basic Usage

Start the framework:
```bash
python Pentest.py
```

Or directly specify a target:
```bash
python Pentest.py --target "192.168.1.100"
```

### Commands

- `start <target>` - Start penetration testing on the target
- `status` - View current session status
- `help` - Show help information
- `quit` - Exit the program

### Interactive Mode

During task execution, you can:
- Enter additional information to pause and replan
- Press `Ctrl+C` to pause monitoring (tasks continue in background)
- Type `q` or `quit` to exit

### UI Modes

The framework supports two UI modes:

1. **Textual TUI** (Recommended): Modern terminal UI with no jitter
   - Automatically used if Textual is installed
   - Install: `pip install textual textual-dev`

2. **Simple Log Mode**: Fallback scrolling log mode
   - Use `--simple` flag to force simple mode

## Architecture

### Components

- **Master Controller**: Orchestrates the entire kill chain execution
- **Agent Pool**: Specialized agents for each stage (Recon, Weaponize, Delivery, Exploit, Install, C2, Objectives)
- **Todo Manager**: Manages task lists and execution state
- **State Manager**: Tracks global context and session state
- **Tool Adapters**: Interfaces with penetration testing tools (nmap, etc.)

### Kill Chain Stages

1. **Reconnaissance**: Information gathering and target discovery
2. **Weaponization**: Payload and exploit preparation
3. **Delivery**: Payload delivery mechanisms
4. **Exploitation**: Vulnerability exploitation
5. **Installation**: Persistence mechanisms
6. **Command & Control**: C2 channel establishment
7. **Actions on Objectives**: Final objective completion

## Project Structure

```
LLM-based-Penetration-Testing/
├── Pentest.py              # Main entry point
├── configs/                 # Configuration files
│   └── llm_runtime.json    # LLM and UI configuration
├── src/
│   ├── agents/             # Agent implementations
│   ├── core/               # Core controllers and managers
│   ├── framework/          # Framework initialization
│   ├── ui/                 # User interface (Textual TUI)
│   ├── utils/              # Utilities (including i18n)
│   └── tools/              # Penetration testing tools
├── pentest_events/         # Event storage and database
└── requirements.txt         # Python dependencies
```

## Internationalization

The framework includes comprehensive internationalization support:

- **English (en)**: Default language
- **Chinese (zh)**: Full Chinese translation

All UI elements, log messages, and user-facing text are translated. Language is configured in `configs/llm_runtime.json` under `ui.language`.

## Development

### Adding New Translations

Translations are managed in `src/utils/i18n.py`. To add a new translation:

1. Add the key to both `TRANSLATIONS["en"]` and `TRANSLATIONS["zh"]`
2. Use `t("key.name")` in code to retrieve translations

### Extending Agents

New agents can be added by:
1. Creating a new agent class in `src/agents/`
2. Registering it in the agent pool
3. Adding corresponding kill chain stage mapping

## Security Notes

⚠️ **Important**: This framework is designed for authorized penetration testing only. Ensure you have proper authorization before testing any target.

- Use only in authorized environments
- Review and understand all generated payloads before execution
- Monitor all network activity
- Follow responsible disclosure practices

## License

See LICENSE file for details.

## Contributing

Contributions are welcome! Please ensure:
- Code follows existing style
- Tests are added for new features
- Documentation is updated
- Translations are added for new UI text

## Support

For issues and questions, please open an issue on the repository.


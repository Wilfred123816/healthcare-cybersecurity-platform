Healthcare Cybersecurity Platform

An AI-powered healthcare cybersecurity and cyber-resilience platform designed to support the analysis of security events across healthcare environments. The project brings together identity, endpoint, network, and electronic health record (EHR) data to support security monitoring, threat detection, evidence trust assessment, and incident investigation.

Project Overview

Healthcare systems depend on connected applications, devices, identities, networks, and patient information. This platform explores how these data sources can be used together to identify suspicious activity and support cybersecurity investigations.

The project includes a FastAPI backend, a React frontend, PostgreSQL database integration, automated tests, Docker-based deployment, and benchmark scripts for evaluating system performance and detection behaviour.

Main Features

- **Security event processing:** Work with identity, endpoint, network, and EHR-related events.
- **Threat detection:** Evaluate suspicious activities and potential attack scenarios.
- **Evidence trust assessment:** Explore the effects of evidence quality, integrity, provenance, and poisoned evidence on detection.
- **Incident investigation:** Provide API support for security investigations and related analysis.
- **Attack-path analysis:** Support analysis of relationships between events and potential attack paths.
- **Performance evaluation:** Run benchmarks for detection, API performance, reliability, scalability, and evidence quality.
- **Web interface:** Provide a frontend for interacting with the platform.
- **Container deployment:** Use Docker Compose to run the main application services.

The platform is a research and development project. Detection results should be validated against appropriate test data before being used in a real healthcare environment.

Technology Stack

| Component | Technology |
|---|---|
| Backend API | Python, FastAPI |
| Frontend | React, Vite, JavaScript |
| Database | PostgreSQL |
| Data processing | Python, pandas |
| API testing | pytest, HTTPX |
| Frontend checks | oxlint, Vite build |
| Deployment | Docker, Docker Compose |
| Version control and CI/CD | Git, GitHub Actions |

Project Structure

```text
healthcare-cybersecurity-platform/
├── .github/
│   └── workflows/        # CI/CD workflows
├── Backend/
│   └── app/
│       ├── api/
│       │   └── routes/   # API route modules
│       └── main.py       # FastAPI application
├── benchmarks/           # Benchmark-related files
├── data/                 # Project datasets
├── docker/               # Docker-related resources
├── docs/                 # Project documentation
├── experiments/          # Experimental work
├── frontend/             # React and Vite frontend
├── scripts/
│   └── benchmark/        # Benchmark scripts
├── src/                  # Supporting source code
├── tests/                # Automated tests
├── .env.example          # Example environment configuration
├── docker-compose.yml    # Multi-service deployment
└── requirements.txt      # Python dependencies
```

Prerequisites

Install the following tools before running the project:

- Python 3.12 or a compatible version supported by the project.
- Node.js and npm.
- PostgreSQL for local database development, or Docker with Docker Compose for container-based deployment.
- Git.

Installation and Local Development

1. Clone the repository

```bash
git clone https://github.com/Wilfred123816/healthcare-cybersecurity-platform.git
cd healthcare-cybersecurity-platform
```

2. Set up the Python environment

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

3. Configure environment variables

Create your local `.env` file using the example configuration:

```powershell
Copy-Item .env.example .env
```

Edit `.env` and enter the configuration required for your environment, including the database connection details.

Do not commit `.env` or publish database passwords, API keys, or other secrets. Use `.env.example` to document the variable names required by the project, without including real credentials.

4. Start the backend

From the project root, run:

```powershell
python -m uvicorn Backend.app.main:app --reload
```

The API should start at:

- API root: `http://127.0.0.1:8000/`
- Health check: `http://127.0.0.1:8000/api/health`
- Interactive API documentation: `http://127.0.0.1:8000/docs`

The health endpoint is expected to return:

```json
{
  "status": "healthy"
}
```

Database-backed features may require PostgreSQL and the project database to be configured and initialized before they can be used.

5. Start the frontend

Open another PowerShell terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Open the local address printed by Vite in the terminal. Confirm that the frontend's API configuration points to the running backend.

Running with Docker Compose

Docker Compose provides a way to run the database, database initialization service, backend, and frontend together.

From the project root, ensure Docker Desktop is running and your `.env.docker` file has the required configuration. Then run:

```powershell
docker compose up --build -d
```

Check the running services:

```powershell
docker compose ps
```

View service logs:

```powershell
docker compose logs --tail 100
```

To follow the logs:

```powershell
docker compose logs -f
```

The frontend is configured to be served at:

`http://localhost:8080`

Check the health endpoint through the available application routing:

`http://localhost:8080/api/health`

To stop the services:

```powershell
docker compose down
```

To remove the database volume as well, use caution: this permanently removes the database data stored in that Docker volume.

```powershell
docker compose down -v
```

API Overview

The FastAPI application includes route modules for:

- Events and unified events.
- Threat detection.
- Evidence trust assessment and trust-aware detection.
- Incident investigation.
- Attack-path analysis.
- Dashboard data.

For the complete list of available endpoints, use the interactive API documentation at `/docs` when the backend is running directly, or inspect the application's OpenAPI schema.

Testing

Run the backend test suite from the project root:

```powershell
python -m pytest tests -v
```

The core API tests cover the application root, health endpoint, and OpenAPI application metadata. Run the tests in the same environment used for development, with any required database configuration in place.

For the frontend, run:

```powershell
cd frontend
npm ci
npm run lint
npm run build
```

These commands install the frontend dependencies, check the source code, and build the production frontend.

Benchmarking

The repository includes scripts for evaluating different aspects of the platform. Run them from the project root unless a script's instructions specify otherwise.

| Script | Purpose |
|---|---|
| `benchmark_detection.py` | Evaluate baseline detection results. |
| `benchmark_trust_aware.py` | Evaluate trust-aware detection. |
| `benchmark_poisoned_evidence.py` | Examine detection under poisoned-evidence conditions. |
| `benchmark_degraded_evidence.py` | Evaluate the impact of degraded evidence. |
| `benchmark_api_performance.py` | Measure API performance. |
| `benchmark_api_reliability.py` | Evaluate API reliability. |
| `benchmark_api_scalability.py` | Evaluate API scalability. |
| `compare_detection_results.py` | Compare detection results. |
| `consolidate_benchmarks.py` | Combine benchmark summaries. |

For example, run a baseline detection benchmark with:

```powershell
python scripts/benchmark/benchmark_detection.py
```

Run other benchmarks in the same way by replacing the script filename with the required script.

The scripts save results as JSON files. Check each script's output message for the exact destination. Benchmark results should be interpreted alongside the dataset, scenario definitions, configuration, and evaluation method used.

Do not compare results from different runs without checking that their test data and evaluation settings are comparable.

Security and Responsible Use

This project is intended for development, testing, and research. Use synthetic or appropriately authorised data when testing the platform.

Before using the platform in a real healthcare environment, further work would be needed to validate detection quality, access controls, privacy protections, audit logging, operational reliability, and response procedures. Automated findings should be reviewed by qualified personnel before consequential action is taken.

Never publish real patient information, passwords, access tokens, private keys, or sensitive production logs in the repository.

Continuous Integration

The repository includes GitHub Actions workflows for automated checks. These workflows can be used to verify backend tests, Python compilation, frontend linting and builds, and Docker image builds.

Check the **Actions** tab in the GitHub repository to review the latest workflow runs and diagnose any failed checks.

Contributing

1. Create a branch for your change.
2. Make the change and add tests where appropriate.
3. Run the relevant backend tests and frontend checks.
4. Review the changes for secrets and sensitive data.
5. Open a pull request with a clear description of the change.

License

Add the project's chosen open-source license before distributing or reusing the code. Until a license is included, do not assume that the repository grants permission for unrestricted reuse.

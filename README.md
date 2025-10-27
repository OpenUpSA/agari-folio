

# Agari-Folio

![Overture Genomics Data Stack](overture-stack.svg)

Agari-Folio is a core service in the Overture Genomics Data stack, providing robust project management and granular role-based access control for genomics data workflows.

## Features
- Project and study management
- Fine-grained permissions and roles
- Organization and user management
- RESTful API with JWT authentication
- Integration with Keycloak for identity management
- Proxy for Overture services (SONG and SCORE)

## API Documentation

Interactive API documentation (Swagger UI) is available at:

```
http://<your-host>:<port>/docs
```

Replace `<your-host>` and `<port>` with your deployment details.

## Proxy for Overture Services SONG and SCORE

This service also acts as a proxy for the Overture services SONG and SCORE, facilitating secure and authenticated access to these services through Agari-Folio's permission system.

## Development

### Install or upgrade dependencies:

(Working in a python virtual environment is recommended)

```
pip install -U  --upgrade-strategy=eager requirements.txt
```

### Running the app

Configure environment variables for accessing the backing services, e.g. using a .env file or direnv.

See settings.py for the variables.

Run a local server with

```
python app.py
```

### Tests

Run tests using pytest:

```
pytest
```

It'll discover the tests in the `test` directory, e.g. modules beginning with `test_`. Reusable fixtures are generally defined in conftest.py.


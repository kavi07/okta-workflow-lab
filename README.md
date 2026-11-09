# Okta Workflow Lab

Build and regression-test a read-only AD offboarding preview for Okta Workflows.

When an AD account is disabled, an IAM engineer needs to know which Okta identity an event would affect, whether that account is protected, and how the flow handles missing or ambiguous inputs. This lab turns a Windows Security Event 4725 into a minimal request, applies those checks against a synthetic inventory, and verifies the JSON response produced by a sandbox flow.

## Try it locally

Requires Python 3.10 or later. The CLI runs locally with the Python standard library and needs no tenant, credentials, or network connection. On Windows, use `py -3` in place of `python3` if needed.

```sh
python3 workflow_lab.py normalize examples/event-4725.xml
python3 workflow_lab.py replay examples/cases.json examples/inventory.json
python3 -m unittest discover -s tests -v
```

The sample event maps to an active lab identity and yields the following response.

```json
{"decision":"would_suspend","reason":"active_identity"}
```

`would_suspend` is a preview outcome. The CLI and both flow recipes leave accounts, sessions, and application assignments untouched.

## Test an Okta Workflows implementation

Build the [preview endpoint and identity helper](docs/workflows.md) in a sandbox org. Use these commands to generate a request and check the response body you capture from that flow.

```sh
python3 workflow_lab.py request examples/cases.json protected
python3 workflow_lab.py check examples/cases.json protected response.json
```

Use the bundled sample response to try the `active` case locally.

```sh
python3 workflow_lab.py check examples/cases.json active examples/active-response.json
```

Exit status `0` means the result matches the fixture. Status `1` means a valid response differs or at least one replay case failed. Status `2` means the command or its input could not be processed. The checker compares both response keys exactly and flags extra fields, including an accidentally exposed user ID.

## Repository guide

| Path | Purpose |
| --- | --- |
| [docs/workflows.md](docs/workflows.md) | Request contract, card-level recipes, decision table, and sandbox validation steps |
| [examples/](examples/) | Synthetic Windows event, identity inventory, casebook, and sample response |
| [tests/](tests/) | Local tests for event parsing, inventory validation, and the CLI |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Runs the regression checks on pushes and pull requests |

The two Workflows recipes are built manually in the console. This initial version was verified locally against synthetic data. A sandbox Workflows run is a separate validation step.

## Contributing

For a bug report or pull request, include a synthetic fixture, the expected decision, and the actual decision. Keep tenant URLs, invoke tokens, event logs, and real identity data out of issues and pull requests. Run the replay and unit tests after changing the decision rules. When the contract changes, update the casebook and card recipes together.

Independent project, licensed under [MIT](LICENSE).

import yaml

def load_config(file_path="config.yaml"):
    """Loads the YAML config file and returns a dictionary."""
    with open(file_path, "r") as file:
        return yaml.safe_load(file)

# Load configuration once when imported
config = load_config()

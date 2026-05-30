import os
import yaml


def load_rules(rules_dir="rules"):
    rules = []

    for root, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith((".yml", ".yaml")):
                path = os.path.join(root, file)

                with open(path, "r", encoding="utf-8") as f:
                    rule = yaml.safe_load(f)
                    rule["file_path"] = path
                    rules.append(rule)

    return rules

import argparse
import logging
import os
import sys
import hcl2
import yaml
from deepdiff import DeepDiff

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define exception classes for custom errors
class ComplianceCheckError(Exception):
    """Base class for compliance check errors."""
    pass

class InvalidInputError(ComplianceCheckError):
    """Raised when input is invalid."""
    pass

# This FileNotFoundError is a new class that shadows the builtin inside
# this module. The loaders raise it, and main catches it through the
# ComplianceCheckError base. Anything outside this file that catches
# the builtin FileNotFoundError will not catch this one.
class FileNotFoundError(ComplianceCheckError):
    """Raised when a file is not found."""
    pass

class ParsingError(ComplianceCheckError):
    """Raised when parsing a file fails."""
    pass

class RuleViolationError(ComplianceCheckError):
    """Raised when a compliance rule is violated."""
    pass


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="IaC Compliance Checker")
    parser.add_argument("-i", "--input", dest="input_file", required=True,
                        help="Path to the Terraform (HCL) IaC configuration file.")
    parser.add_argument("-r", "--rules", dest="rules_file", required=True,
                        help="Path to the compliance rules file (YAML).")
    parser.add_argument("-o", "--output", dest="output_file",
                        help="Path to the output file for report (optional).")
    parser.add_argument("-f", "--format", dest="format", choices=['yaml', 'text'], default='text',
                        help="Output format (yaml or text), default is text.")  # Added output format option
    return parser


def load_iac_file(file_path):
    """
    Loads and parses the IaC configuration file.  Currently supports Terraform (HCL2).

    Args:
        file_path (str): Path to the IaC configuration file.

    Returns:
        dict: Parsed IaC configuration data.

    Raises:
        FileNotFoundError: If the file does not exist.
        ParsingError: If parsing fails.
    """
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"IaC file not found: {file_path}")

        with open(file_path, 'r') as f:
            file_content = f.read()

        try:
            # Every input is parsed as Terraform HCL.
            data = hcl2.loads(file_content)
            return data
        except Exception as e:
             raise ParsingError(f"Error parsing IaC file: {file_path}. Error: {e}")

    except FileNotFoundError as e:
        logging.error(str(e))
        raise
    except ParsingError as e:
        logging.error(str(e))
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading IaC file: {e}")
        raise


def load_rules_file(file_path):
    """
    Loads the compliance rules file (YAML).

    Args:
        file_path (str): Path to the compliance rules file.

    Returns:
        dict: Compliance rules data.

    Raises:
        FileNotFoundError: If the file does not exist.
        ParsingError: If parsing fails.
    """
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Rules file not found: {file_path}")

        with open(file_path, 'r') as f:
            try:
                rules = yaml.safe_load(f)
                return rules
            except yaml.YAMLError as e:
                raise ParsingError(f"Error parsing rules file: {file_path}. Error: {e}")

    except FileNotFoundError as e:
        logging.error(str(e))
        raise
    except ParsingError as e:
        logging.error(str(e))
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading rules file: {e}")
        raise


def check_compliance(iac_data, rules):
    """
    Checks the IaC configuration against the compliance rules.

    Args:
        iac_data (dict): Parsed IaC configuration data.
        rules (dict): Compliance rules data.

    Returns:
        list: A list of violations found.
    """
    violations = []
    if not isinstance(iac_data, dict):
        logging.error(f"Invalid IaC data type: {type(iac_data)}.  Expected dict.")
        raise InvalidInputError("IaC data must be a dictionary.")

    if not isinstance(rules, dict):
        logging.error(f"Invalid rules data type: {type(rules)}. Expected dict.")
        raise InvalidInputError("Rules data must be a dictionary.")

    resources = list(_iter_resources(iac_data))
    # No resources at all is an error, not a clean pass. A Terraform file
    # with only variables and outputs has nothing this checker can check,
    # and reporting no violations for it would be a false pass.
    if not resources:
        logging.error("No resources found in the IaC data; nothing was checked.")
        raise InvalidInputError("No resources found in the IaC data; nothing was checked.")

    for resource_type, rule_set in rules.items():
        if not isinstance(rule_set, dict):
            logging.error(f"Invalid rule set for resource type '{resource_type}'. Expected a dictionary of property rules.")
            raise InvalidInputError(f"Rule set for resource type '{resource_type}' must be a dictionary.")
        type_matched = False
        for matched_type, resource_name, resource in resources:
            if matched_type != resource_type:
                continue
            type_matched = True
            for rule_name, rule_value in rule_set.items():
                if rule_name not in resource:
                    violations.append({
                        "resource_type": resource_type,
                        "resource_name": resource_name,
                        "rule_name": rule_name,
                        "expected_value": rule_value,
                        "actual_value": None,
                        "difference": f"{rule_name} is absent; expected {rule_value!r}"
                    })
                    continue
                # DeepDiff compares the whole property value against the rule value.
                # For a nested block that means exact equality apart from ordering:
                # extra keys in the resource that the rule does not mention still
                # produce a difference and therefore a violation. A rule is a complete
                # expected value for the property, not a subset to check within it.
                diff = DeepDiff(resource[rule_name], rule_value, ignore_order=True)
                if diff:
                    violations.append({
                        "resource_type": resource_type,
                        "resource_name": resource_name,
                        "rule_name": rule_name,
                        "expected_value": rule_value,
                        "actual_value": resource[rule_name],
                        "difference": str(diff)
                    })
        # A rule set whose type matches no resource is a warning, not a
        # violation, and does not move the exit code. A misspelled resource
        # type in the rules file therefore passes the run, with this log line
        # as the only trace that the rules were never applied.
        if not type_matched:
            logging.warning(
                f"Rule set for resource type '{resource_type}' matched no resource "
                "in the IaC data; those rules were not checked."
            )
    return violations


def _iter_resources(iac_data):
    """
    Yields (resource_type, resource_name, body) for each resource in the
    parsed IaC data.

    hcl2.loads nests Terraform resources under a top level "resource"
    key as a list of {resource_type: [{label: body}]}, so the blocks are
    walked into flat resources here. The flat shape the rules were
    written against ({resource_type: [body, ...]}) is accepted as well.
    Parser metadata keys starting with "__" are dropped from bodies.
    """
    def clean(body):
        return {k: v for k, v in body.items() if not str(k).startswith("__")}

    resource_blocks = iac_data.get("resource")
    if isinstance(resource_blocks, dict):
        resource_blocks = [resource_blocks]
    if isinstance(resource_blocks, list):
        for block in resource_blocks:
            if not isinstance(block, dict):
                continue
            for resource_type, labelled in block.items():
                entries = labelled if isinstance(labelled, list) else [labelled]
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    # The labelled shape is recognised by shape alone: an entry whose
                    # values are all dicts is read as label to body pairs. A resource body
                    # whose properties all happen to be nested blocks fits that test too
                    # and would be walked as if its properties were labels.
                    if entry and all(isinstance(v, dict) for v in entry.values()):
                        for label, body in entry.items():
                            if isinstance(body, dict):
                                yield resource_type, label, clean(body)
                    else:
                        yield resource_type, entry.get("name", "N/A"), clean(entry)

    for key, value in iac_data.items():
        if key == "resource":
            continue
        entries = value if isinstance(value, list) else [value]
        for entry in entries:
            if isinstance(entry, dict):
                yield key, entry.get("name", "N/A"), clean(entry)



def output_report(violations, output_file=None, format='text'):
    """
    Outputs the compliance report to the console or a file.

    Args:
        violations (list): A list of compliance violations.
        output_file (str, optional): Path to the output file. Defaults to None (console).
        format (str, optional): Output format ('yaml' or 'text'). Defaults to 'text'.
    """
    report = ""
    if violations:
        if format == 'yaml':
            report = yaml.dump(violations, indent=2)  # Generate YAML output
        else:  # Default to text format
            report += "Compliance Violations:\n"
            for violation in violations:
                report += f"  Resource Type: {violation['resource_type']}\n"
                report += f"  Resource Name: {violation['resource_name']}\n"
                report += f"  Rule Violated: {violation['rule_name']}\n"
                report += f"  Expected Value: {violation['expected_value']}\n"
                report += f"  Actual Value: {violation['actual_value']}\n"
                report += f"  Difference: {violation['difference']}\n"
                report += "---\n"
    else:
        report = "No compliance violations found."

    if output_file:
        # A failed write raises; main turns it into exit 1.
        with open(output_file, 'w') as f:
            f.write(report)
        logging.info(f"Report written to: {output_file}")
    else:
        print(report)



def main():
    """
    Main function to orchestrate the IaC compliance check.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        # Input validation (example - more needed)
        if not args.input_file or not args.rules_file:
            raise InvalidInputError("Both input file and rules file are required.")

        if args.output_file:
            resolved_output = os.path.realpath(args.output_file)
            if resolved_output in (os.path.realpath(args.input_file), os.path.realpath(args.rules_file)):
                raise InvalidInputError(f"Output path resolves to an input file, refusing to overwrite it: {args.output_file}")

        iac_data = load_iac_file(args.input_file)
        if not iac_data:
            raise InvalidInputError("IaC file parsed to an empty structure; nothing was checked.")
        rules = load_rules_file(args.rules_file)
        violations = check_compliance(iac_data, rules)
        output_report(violations, args.output_file, args.format)

        if violations:
            logging.warning("Compliance violations found.") # Reduced severity to warning
            sys.exit(1)  # Exit with a non-zero code to indicate violations
        else:
            logging.info("No compliance violations found.")
            sys.exit(0) # Exit with zero to indicate success

    except ComplianceCheckError as e:
        logging.error(f"Compliance check failed: {e}")
        sys.exit(1)  # Exit with a non-zero code on error
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)  # Exit with a non-zero code on unexpected error



if __name__ == "__main__":
    # Example Usage:
    # To run the script:
    # python3 main.py -i example.tf -r rules.yaml -o report.txt
    #
    # Example Terraform file (example.tf):
    # resource "aws_s3_bucket" "example" {
    #   bucket = "my-example-bucket"
    #   acl    = "public-read" #This is violating our compliance rule
    # }
    #
    # Example Rules file (rules.yaml):
    # aws_s3_bucket:
    #   acl: "private"
    #
    # This will check the example.tf file against the rules.yaml,
    # report any violations, and optionally write the report to report.txt.
    #
    # If a resource "aws_s3_bucket" has acl: "public-read", it will be flagged
    # as a violation because the rule specifies it should be "private".

    main()
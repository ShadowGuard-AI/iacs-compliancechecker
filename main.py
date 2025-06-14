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
                        help="Path to the IaC configuration file (e.g., Terraform, CloudFormation).")
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
            # Assume Terraform (HCL2) for now.  Expand for other formats later (e.g., CloudFormation)
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

    # Basic example: Check if resource properties match expected values.
    # This will need to be expanded significantly to handle more complex rules.
    for resource_type, rule_set in rules.items():
        if resource_type in iac_data:
            for resource in iac_data[resource_type]:
                for rule_name, rule_value in rule_set.items():
                    if rule_name in resource:
                         diff = DeepDiff(resource[rule_name], rule_value, ignore_order=True)
                         if diff:
                             violations.append({
                                 "resource_type": resource_type,
                                 "resource_name": resource.get("name", "N/A"),
                                 "rule_name": rule_name,
                                 "expected_value": rule_value,
                                 "actual_value": resource[rule_name],
                                 "difference": diff
                             })
    return violations



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
        try:
            with open(output_file, 'w') as f:
                f.write(report)
            logging.info(f"Report written to: {output_file}")
        except Exception as e:
            logging.error(f"Error writing report to file: {e}")
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

        iac_data = load_iac_file(args.input_file)
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
    # python iac_compliance_checker.py -i example.tf -r rules.yaml -o report.txt
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
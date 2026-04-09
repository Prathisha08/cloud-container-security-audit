import subprocess
from typing import List, Dict, Any

import boto3

from scans.docker_scan import scan_docker_image


def list_ecr_images(repository_name: str, max_results: int = 10) -> List[str]:
    ecr = boto3.client("ecr")
    image_refs = []

    paginator = ecr.get_paginator("describe_images")
    pages = paginator.paginate(repositoryName=repository_name)

    count = 0
    for page in pages:
        for detail in page.get("imageDetails", []):
            tags = detail.get("imageTags", [])
            for tag in tags:
                image_refs.append(f"{repository_name}:{tag}")
                count += 1
                if count >= max_results:
                    return image_refs

    return image_refs


def get_ecr_registry_uri() -> str:
    ecr = boto3.client("ecr")
    sts = boto3.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    region = ecr.meta.region_name

    return f"{account_id}.dkr.ecr.{region}.amazonaws.com"


def ecr_login() -> bool:
    try:
        ecr = boto3.client("ecr")
        token_response = ecr.get_authorization_token()

        auth_data = token_response["authorizationData"][0]
        username, password = (
            __import__("base64").b64decode(auth_data["authorizationToken"]).decode().split(":")
        )
        registry = auth_data["proxyEndpoint"]

        result = subprocess.run(
            ["docker", "login", "-u", username, "-p", password, registry],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            print("ECR login failed:")
            print(result.stderr)
            return False

        return True

    except Exception as e:
        print(f"ECR login error: {e}")
        return False


def scan_ecr_repository(repository_name: str, max_results: int = 5) -> List[Dict[str, Any]]:
    findings = []

    try:
        registry_uri = get_ecr_registry_uri()

        if not ecr_login():
            return findings

        image_refs = list_ecr_images(repository_name, max_results=max_results)

        if not image_refs:
            print(f"No images found in ECR repository: {repository_name}")
            return findings

        for image_ref in image_refs:
            full_image = f"{registry_uri}/{image_ref}"

            print(f"Pulling ECR image: {full_image}")
            pull_result = subprocess.run(
                ["docker", "pull", full_image],
                capture_output=True,
                text=True,
                check=False
            )

            if pull_result.returncode != 0:
                print(f"Failed to pull image: {full_image}")
                print(pull_result.stderr)
                continue

            print(f"Scanning ECR image: {full_image}")
            image_findings = scan_docker_image(full_image)
            findings.extend(image_findings)

    except Exception as e:
        print(f"ECR scan error: {e}")

    return findings
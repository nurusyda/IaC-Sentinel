#!/usr/bin/env bash
set -euo pipefail

# ── CONFIG — edit these once ──────────────────────────────────────────────
AWS_ACCOUNT_ID="224092145786"        # e.g. 123456789012
AWS_REGION="us-east-1"                # e.g. ap-southeast-1
ECR_REPO="iac-sentinel"
EB_APP_NAME="iac-sentinel"
EB_ENV_NAME="iac-sentinel-prod"
# ─────────────────────────────────────────────────────────────────────────

ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}"
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "manual")
IMAGE_TAG="${GIT_SHA}-$(date +%Y%m%d%H%M%S)"

echo "==> [1/5] Authenticating Docker with ECR..."
aws ecr get-login-password --region "${AWS_REGION}" \
  | docker login --username AWS --password-stdin \
    "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

echo "==> [2/5] Building image: ${ECR_URI}:${IMAGE_TAG}"
docker build \
  --platform linux/amd64 \
  -t "${ECR_REPO}:${IMAGE_TAG}" \
  .

echo "==> [3/5] Tagging and pushing to ECR..."
docker tag "${ECR_REPO}:${IMAGE_TAG}" "${ECR_URI}:${IMAGE_TAG}"
docker tag "${ECR_REPO}:${IMAGE_TAG}" "${ECR_URI}:latest"
docker push "${ECR_URI}:${IMAGE_TAG}"
docker push "${ECR_URI}:latest"

echo "==> [4/5] Updating Dockerrun.aws.json with new image tag..."
sed "s|:latest|:${IMAGE_TAG}|g" Dockerrun.aws.json > Dockerrun.aws.json.deploy

echo "==> [5/5] Creating EB application version and deploying..."
BUNDLE="deploy-${IMAGE_TAG}.zip"

# Notice: 03-security.config is removed from here for our HTTP test
zip "${BUNDLE}" \
  Dockerrun.aws.json.deploy \
  .ebextensions/01-env-validation.config \
  .ebextensions/02-healthcheck.config

cp Dockerrun.aws.json Dockerrun.aws.json.bak
cp Dockerrun.aws.json.deploy Dockerrun.aws.json
zip "${BUNDLE}" Dockerrun.aws.json
mv Dockerrun.aws.json.bak Dockerrun.aws.json
rm Dockerrun.aws.json.deploy

S3_BUCKET=$(aws elasticbeanstalk describe-storage-location \
  --query 'S3Bucket' --output text 2>/dev/null || echo "")

if [ -z "${S3_BUCKET}" ]; then
  echo "[WARN] Could not detect EB S3 bucket. Using eb deploy fallback..."
  eb deploy "${EB_ENV_NAME}" --label "v-${IMAGE_TAG}"
else
  aws s3 cp "${BUNDLE}" "s3://${S3_BUCKET}/${EB_APP_NAME}/${BUNDLE}"
  aws elasticbeanstalk create-application-version \
    --application-name "${EB_APP_NAME}" \
    --version-label "v-${IMAGE_TAG}" \
    --source-bundle "S3Bucket=${S3_BUCKET},S3Key=${EB_APP_NAME}/${BUNDLE}"
  aws elasticbeanstalk update-environment \
    --environment-name "${EB_ENV_NAME}" \
    --version-label "v-${IMAGE_TAG}"
fi

rm -f "${BUNDLE}"

echo ""
echo "✓ Deployed version v-${IMAGE_TAG} to ${EB_ENV_NAME}"
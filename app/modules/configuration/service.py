"""Configuration Service - job generation and device apply."""
import logging
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session
from app.models import (
    ArchitectureDesignVersion,
    ConfigurationJob,
    ConfigurationObject,
    Asset,
)
from app.modules.configuration.templates import generate_commands

logger = logging.getLogger(__name__)


class ConfigurationService:
    """Configuration Job Service."""

    @staticmethod
    def list_jobs(db: Session):
        return db.query(ConfigurationJob).order_by(ConfigurationJob.created_at.desc()).all()

    @staticmethod
    def get_job(db: Session, job_id: int) -> Optional[ConfigurationJob]:
        return db.query(ConfigurationJob).filter(ConfigurationJob.id == job_id).first()

    @staticmethod
    def get_object(db: Session, object_id: int) -> Optional[ConfigurationObject]:
        return db.query(ConfigurationObject).filter(ConfigurationObject.id == object_id).first()

    @staticmethod
    def generate_job(
        db: Session, version: ArchitectureDesignVersion, name: str, user_id: Optional[int]
    ) -> ConfigurationJob:
        """Generate one ConfigurationObject per mapped component in this version.

        Components with no real asset mapped yet are skipped - there's nothing
        to push configuration to until the design is built.
        """
        job = ConfigurationJob(design_version_id=version.id, name=name, status="generated", created_by=user_id)
        db.add(job)
        db.flush()

        relationships_by_component: dict[int, list] = {}
        for relationship in version.relationships_:
            relationships_by_component.setdefault(relationship.source_component_id, []).append(relationship)
            relationships_by_component.setdefault(relationship.destination_component_id, []).append(relationship)

        for component in version.components:
            mapping = component.asset_mapping
            if not mapping or not mapping.asset_id:
                continue
            asset = db.query(Asset).filter(Asset.id == mapping.asset_id).first()
            if not asset:
                continue

            device_type = asset.inferred_device_type
            commands = generate_commands(component, relationships_by_component.get(component.id, []), device_type)

            db.add(
                ConfigurationObject(
                    configuration_job_id=job.id,
                    design_component_id=component.id,
                    asset_id=asset.id,
                    asset_name=asset.asset_name,
                    device_type=device_type,
                    generated_config="\n".join(commands),
                    apply_status="pending",
                )
            )

        db.commit()
        db.refresh(job)
        return job

    @staticmethod
    def apply_object(
        db: Session,
        obj: ConfigurationObject,
        username: str,
        password: str,
        secret: Optional[str],
        port: int,
        user_id: Optional[int],
    ) -> ConfigurationObject:
        """Push a generated configuration to its target device.

        Reuses the same per-tech hardening executors' execute_commands() that
        the Hardening module already relies on for the same device families -
        no new device connector. Credentials are never stored (matching every
        other device-facing endpoint in this app): they're supplied fresh on
        this call and discarded after use.
        """
        if not obj.asset_id:
            raise ValueError("This configuration object has no target asset")
        asset = db.query(Asset).filter(Asset.id == obj.asset_id).first()
        if not asset or not asset.ip_address:
            raise ValueError("Target asset has no IP address configured")

        commands = obj.generated_config.splitlines()

        try:
            if obj.device_type == "cisco":
                from app.modules.cisco.hardening.ssh_executor import CiscoHardeningExecutor
                with CiscoHardeningExecutor(ip=asset.ip_address, username=username, password=password, secret=secret) as ex:
                    result = ex.execute_commands(commands)
            elif obj.device_type == "fortinet":
                from app.modules.fortinet.hardening.ssh_executor import FortiGateHardeningExecutor
                with FortiGateHardeningExecutor(ip=asset.ip_address, username=username, password=password, port=port) as ex:
                    result = ex.execute_commands(commands)
            else:
                raise ValueError(f"Applying configuration is not supported for device type '{obj.device_type}'")
        except Exception as exc:
            logger.error(f"Configuration apply failed for object {obj.id}: {exc}")
            obj.apply_status = "failed"
            obj.apply_output = str(exc)
            obj.applied_by = user_id
            obj.applied_at = datetime.utcnow()
            db.commit()
            db.refresh(obj)
            return obj

        obj.apply_status = "success" if result.get("success") else "failed"
        obj.apply_output = result.get("output") or "\n".join(result.get("errors", []))
        obj.applied_by = user_id
        obj.applied_at = datetime.utcnow()
        db.commit()
        db.refresh(obj)
        return obj

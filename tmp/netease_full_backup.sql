--
-- PostgreSQL database dump
--

\restrict kaDBH2avjay1CyWOhZXouxomLe2lGugDemT4VOaudCMVDfKGYNbXe8Aw4rvIGUP

-- Dumped from database version 18.1
-- Dumped by pg_dump version 18.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: checkstatus; Type: TYPE; Schema: public; Owner: netease
--

CREATE TYPE public.checkstatus AS ENUM (
    'PASS',
    'FAIL',
    'NOT_APPLICABLE',
    'ERROR'
);


ALTER TYPE public.checkstatus OWNER TO netease;

--
-- Name: confidentialitylevelenum; Type: TYPE; Schema: public; Owner: netease
--

CREATE TYPE public.confidentialitylevelenum AS ENUM (
    'PUBLIC',
    'INTERNAL',
    'CONFIDENTIAL',
    'CRITICAL'
);


ALTER TYPE public.confidentialitylevelenum OWNER TO netease;

--
-- Name: devicetype; Type: TYPE; Schema: public; Owner: netease
--

CREATE TYPE public.devicetype AS ENUM (
    'CISCO',
    'LINUX',
    'WINDOWS',
    'FORTINET'
);


ALTER TYPE public.devicetype OWNER TO netease;

--
-- Name: moduleenum; Type: TYPE; Schema: public; Owner: netease
--

CREATE TYPE public.moduleenum AS ENUM (
    'DASHBOARD',
    'ASSET_REQUIREMENT',
    'ASSET_LIST',
    'ASSET_AUTO_DISCOVERY',
    'USER_MANAGEMENT',
    'AUDITING',
    'HARDENING',
    'LOGS'
);


ALTER TYPE public.moduleenum OWNER TO netease;

--
-- Name: relationtypeenum; Type: TYPE; Schema: public; Owner: netease
--

CREATE TYPE public.relationtypeenum AS ENUM (
    'NETWORK_LINK',
    'APP_DEPENDENCY',
    'BACKUP_LINK',
    'POWER_SOURCE',
    'LOGICAL_CONNECTION'
);


ALTER TYPE public.relationtypeenum OWNER TO netease;

--
-- Name: risklevelenum; Type: TYPE; Schema: public; Owner: netease
--

CREATE TYPE public.risklevelenum AS ENUM (
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL'
);


ALTER TYPE public.risklevelenum OWNER TO netease;

--
-- Name: statusenum; Type: TYPE; Schema: public; Owner: netease
--

CREATE TYPE public.statusenum AS ENUM (
    'ACTIVE',
    'STANDBY',
    'DECOMMISSIONED',
    'UNKNOWN'
);


ALTER TYPE public.statusenum OWNER TO netease;

--
-- Name: userrole; Type: TYPE; Schema: public; Owner: netease
--

CREATE TYPE public.userrole AS ENUM (
    'ADMIN',
    'USER',
    'MANAGER',
    'GUEST'
);


ALTER TYPE public.userrole OWNER TO netease;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


ALTER TABLE public.alembic_version OWNER TO netease;

--
-- Name: asset_dependencies; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.asset_dependencies (
    id integer NOT NULL,
    asset_id integer NOT NULL,
    depends_on_id integer NOT NULL,
    relation_type public.relationtypeenum NOT NULL,
    description text
);


ALTER TABLE public.asset_dependencies OWNER TO netease;

--
-- Name: COLUMN asset_dependencies.id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_dependencies.id IS 'Unique identifier for dependency record';


--
-- Name: COLUMN asset_dependencies.asset_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_dependencies.asset_id IS 'The asset that has a dependency (dependent asset)';


--
-- Name: COLUMN asset_dependencies.depends_on_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_dependencies.depends_on_id IS 'The asset that is depended upon (dependency target)';


--
-- Name: COLUMN asset_dependencies.relation_type; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_dependencies.relation_type IS 'Type of relationship (network_link, app_dependency, backup_link, power_source, logical_connection)';


--
-- Name: COLUMN asset_dependencies.description; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_dependencies.description IS 'Additional notes or details about this dependency';


--
-- Name: asset_dependencies_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.asset_dependencies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.asset_dependencies_id_seq OWNER TO netease;

--
-- Name: asset_dependencies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.asset_dependencies_id_seq OWNED BY public.asset_dependencies.id;


--
-- Name: asset_inventory; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.asset_inventory (
    id integer NOT NULL,
    asset_name character varying(200) NOT NULL,
    hostname character varying(200),
    asset_type_id integer NOT NULL,
    asset_role character varying(200),
    manufacturer character varying(200),
    model character varying(200),
    serial_number character varying(200),
    os_name character varying(100),
    os_version character varying(50),
    ip_address character varying(50),
    mac_address character varying(50),
    location_id integer,
    owner_id integer,
    status public.statusenum NOT NULL,
    confidentiality_level public.confidentialitylevelenum,
    risk_level public.risklevelenum,
    last_audit_date date,
    last_patch_date date,
    asset_value numeric(15,2),
    description text,
    user_id integer,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    discovered_fields json DEFAULT '{}'::json
);


ALTER TABLE public.asset_inventory OWNER TO netease;

--
-- Name: COLUMN asset_inventory.id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.id IS 'Unique identifier (asset_id in forms)';


--
-- Name: COLUMN asset_inventory.asset_name; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.asset_name IS 'Name of the asset (e.g., Core-Switch-01, FW-Main)';


--
-- Name: COLUMN asset_inventory.hostname; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.hostname IS 'Network hostname';


--
-- Name: COLUMN asset_inventory.asset_type_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.asset_type_id IS 'FK to asset_types (Firewall, Router, Switch, etc.)';


--
-- Name: COLUMN asset_inventory.asset_role; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.asset_role IS 'Role or purpose of the asset (e.g., Core Network, DMZ Gateway)';


--
-- Name: COLUMN asset_inventory.manufacturer; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.manufacturer IS 'Vendor/manufacturer name (e.g., Cisco, HP, Dell)';


--
-- Name: COLUMN asset_inventory.model; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.model IS 'Model name or number (e.g., Catalyst 9300, ProLiant DL380)';


--
-- Name: COLUMN asset_inventory.serial_number; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.serial_number IS 'Serial number (should be unique)';


--
-- Name: COLUMN asset_inventory.os_name; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.os_name IS 'Operating system name (e.g., Windows Server, Ubuntu, FortiOS)';


--
-- Name: COLUMN asset_inventory.os_version; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.os_version IS 'OS version (e.g., 2019, 22.04, 7.2)';


--
-- Name: COLUMN asset_inventory.ip_address; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.ip_address IS 'IP address (e.g., 10.0.0.1, 192.168.1.100)';


--
-- Name: COLUMN asset_inventory.mac_address; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.mac_address IS 'MAC address (e.g., 00:11:22:33:44:55)';


--
-- Name: COLUMN asset_inventory.location_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.location_id IS 'FK to asset_locations (physical/logical location)';


--
-- Name: COLUMN asset_inventory.owner_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.owner_id IS 'FK to asset_owners (person responsible for asset)';


--
-- Name: COLUMN asset_inventory.status; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.status IS 'Asset status (active, standby, decommissioned, unknown)';


--
-- Name: COLUMN asset_inventory.confidentiality_level; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.confidentiality_level IS 'Data classification (public, internal, confidential, critical)';


--
-- Name: COLUMN asset_inventory.risk_level; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.risk_level IS 'Risk assessment (low, medium, high, critical)';


--
-- Name: COLUMN asset_inventory.last_audit_date; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.last_audit_date IS 'Date of last audit or review';


--
-- Name: COLUMN asset_inventory.last_patch_date; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.last_patch_date IS 'Date of last security patch or update';


--
-- Name: COLUMN asset_inventory.asset_value; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.asset_value IS 'Financial value of the asset (with 2 decimal places)';


--
-- Name: COLUMN asset_inventory.description; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.description IS 'Additional notes or description';


--
-- Name: COLUMN asset_inventory.user_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.user_id IS 'FK to users - determines which user owns this asset';


--
-- Name: COLUMN asset_inventory.created_at; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.created_at IS 'Record creation timestamp';


--
-- Name: COLUMN asset_inventory.updated_at; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.updated_at IS 'Last update timestamp';


--
-- Name: COLUMN asset_inventory.discovered_fields; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_inventory.discovered_fields IS 'Fields populated by auto-discovery (JSON: {field_name: true})';


--
-- Name: asset_inventory_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.asset_inventory_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.asset_inventory_id_seq OWNER TO netease;

--
-- Name: asset_inventory_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.asset_inventory_id_seq OWNED BY public.asset_inventory.id;


--
-- Name: asset_locations; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.asset_locations (
    id integer NOT NULL,
    site_name character varying(200) NOT NULL,
    rack_name character varying(100),
    room character varying(100),
    floor character varying(50),
    network_zone character varying(100),
    vlan_id integer,
    subnet character varying(50),
    description text,
    user_id integer NOT NULL
);


ALTER TABLE public.asset_locations OWNER TO netease;

--
-- Name: COLUMN asset_locations.id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_locations.id IS 'Unique identifier for location';


--
-- Name: COLUMN asset_locations.site_name; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_locations.site_name IS 'Site or building name (e.g., Main DC, Branch Office)';


--
-- Name: COLUMN asset_locations.rack_name; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_locations.rack_name IS 'Rack identifier (e.g., Rack-12, R-A-05)';


--
-- Name: COLUMN asset_locations.room; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_locations.room IS 'Room name or number (e.g., Server Room A, Room 204)';


--
-- Name: COLUMN asset_locations.floor; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_locations.floor IS 'Floor number or name (e.g., 2nd Floor, Basement)';


--
-- Name: COLUMN asset_locations.network_zone; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_locations.network_zone IS 'Network zone or segment (e.g., DMZ, Internal, Management)';


--
-- Name: COLUMN asset_locations.vlan_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_locations.vlan_id IS 'VLAN identifier (e.g., 100, 200)';


--
-- Name: COLUMN asset_locations.subnet; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_locations.subnet IS 'Network subnet in CIDR notation (e.g., 10.0.0.0/24, 192.168.1.0/24)';


--
-- Name: COLUMN asset_locations.description; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_locations.description IS 'Additional notes or description about this location';


--
-- Name: COLUMN asset_locations.user_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_locations.user_id IS 'Reference to users table - determines which user owns this location record';


--
-- Name: asset_locations_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.asset_locations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.asset_locations_id_seq OWNER TO netease;

--
-- Name: asset_locations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.asset_locations_id_seq OWNED BY public.asset_locations.id;


--
-- Name: asset_owners; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.asset_owners (
    id integer NOT NULL,
    full_name character varying(200) NOT NULL,
    department character varying(100),
    role character varying(100),
    email character varying(255),
    phone character varying(50),
    responsibility_level character varying(50),
    user_id integer NOT NULL,
    created_at timestamp without time zone NOT NULL
);


ALTER TABLE public.asset_owners OWNER TO netease;

--
-- Name: COLUMN asset_owners.id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_owners.id IS 'Unique identifier for asset owner';


--
-- Name: COLUMN asset_owners.full_name; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_owners.full_name IS 'Full name of the asset owner';


--
-- Name: COLUMN asset_owners.department; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_owners.department IS 'Department or team name (e.g., IT, Security, Network)';


--
-- Name: COLUMN asset_owners.role; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_owners.role IS 'Job role or position (e.g., Network Manager, Security Admin)';


--
-- Name: COLUMN asset_owners.email; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_owners.email IS 'Contact email address';


--
-- Name: COLUMN asset_owners.phone; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_owners.phone IS 'Contact phone number';


--
-- Name: COLUMN asset_owners.responsibility_level; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_owners.responsibility_level IS 'Level of responsibility (e.g., Primary, Secondary, Backup)';


--
-- Name: COLUMN asset_owners.user_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_owners.user_id IS 'Reference to users table - determines which user owns this owner record';


--
-- Name: COLUMN asset_owners.created_at; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_owners.created_at IS 'Record creation timestamp';


--
-- Name: asset_owners_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.asset_owners_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.asset_owners_id_seq OWNER TO netease;

--
-- Name: asset_owners_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.asset_owners_id_seq OWNED BY public.asset_owners.id;


--
-- Name: asset_security_status; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.asset_security_status (
    id integer NOT NULL,
    asset_id integer NOT NULL,
    antivirus_installed boolean NOT NULL,
    antivirus_status character varying(50),
    firewall_enabled boolean NOT NULL,
    last_patch_date date,
    backup_enabled boolean NOT NULL,
    vulnerability_score double precision,
    compliance_status character varying(50),
    notes text
);


ALTER TABLE public.asset_security_status OWNER TO netease;

--
-- Name: COLUMN asset_security_status.id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_security_status.id IS 'Unique identifier for security status record';


--
-- Name: COLUMN asset_security_status.asset_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_security_status.asset_id IS 'Reference to asset_inventory (one-to-one relationship)';


--
-- Name: COLUMN asset_security_status.antivirus_installed; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_security_status.antivirus_installed IS 'Whether antivirus software is installed';


--
-- Name: COLUMN asset_security_status.antivirus_status; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_security_status.antivirus_status IS 'Status of antivirus (e.g., Active, Outdated, Disabled, Not Applicable)';


--
-- Name: COLUMN asset_security_status.firewall_enabled; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_security_status.firewall_enabled IS 'Whether firewall is enabled';


--
-- Name: COLUMN asset_security_status.last_patch_date; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_security_status.last_patch_date IS 'Date of last security patch or update';


--
-- Name: COLUMN asset_security_status.backup_enabled; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_security_status.backup_enabled IS 'Whether backup is configured and enabled';


--
-- Name: COLUMN asset_security_status.vulnerability_score; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_security_status.vulnerability_score IS 'Vulnerability score (0-10, CVSS or custom scale)';


--
-- Name: COLUMN asset_security_status.compliance_status; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_security_status.compliance_status IS 'Compliance state (e.g., Compliant, Non-Compliant, Partially Compliant, Under Review)';


--
-- Name: COLUMN asset_security_status.notes; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_security_status.notes IS 'Additional security notes or observations';


--
-- Name: asset_security_status_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.asset_security_status_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.asset_security_status_id_seq OWNER TO netease;

--
-- Name: asset_security_status_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.asset_security_status_id_seq OWNED BY public.asset_security_status.id;


--
-- Name: asset_types; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.asset_types (
    id integer NOT NULL,
    type_name character varying(100) NOT NULL,
    category character varying(50) NOT NULL,
    description text
);


ALTER TABLE public.asset_types OWNER TO netease;

--
-- Name: COLUMN asset_types.id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_types.id IS 'شناسه یکتا';


--
-- Name: COLUMN asset_types.type_name; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_types.type_name IS 'نام نوع asset (مثلاً Firewall)';


--
-- Name: COLUMN asset_types.category; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_types.category IS 'دسته‌بندی (Security, Network, Infrastructure, ...)';


--
-- Name: COLUMN asset_types.description; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.asset_types.description IS 'توضیحات اختیاری';


--
-- Name: asset_types_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.asset_types_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.asset_types_id_seq OWNER TO netease;

--
-- Name: asset_types_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.asset_types_id_seq OWNED BY public.asset_types.id;


--
-- Name: audit_checks; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.audit_checks (
    id integer NOT NULL,
    template_id integer NOT NULL,
    check_number character varying(20) NOT NULL,
    title character varying(500) NOT NULL,
    description text,
    command text NOT NULL,
    expected_output text,
    severity character varying(20)
);


ALTER TABLE public.audit_checks OWNER TO netease;

--
-- Name: audit_checks_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.audit_checks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.audit_checks_id_seq OWNER TO netease;

--
-- Name: audit_checks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.audit_checks_id_seq OWNED BY public.audit_checks.id;


--
-- Name: audit_results; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.audit_results (
    id integer NOT NULL,
    session_id integer NOT NULL,
    check_id integer NOT NULL,
    status public.checkstatus NOT NULL,
    actual_output text,
    error_message text,
    checked_at timestamp without time zone
);


ALTER TABLE public.audit_results OWNER TO netease;

--
-- Name: audit_results_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.audit_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.audit_results_id_seq OWNER TO netease;

--
-- Name: audit_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.audit_results_id_seq OWNED BY public.audit_results.id;


--
-- Name: audit_sessions; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.audit_sessions (
    id integer NOT NULL,
    template_id integer NOT NULL,
    user_id integer NOT NULL,
    asset_id integer,
    target_ip character varying(50) NOT NULL,
    device_type public.devicetype NOT NULL,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    status character varying(20),
    total_checks integer,
    passed_checks integer,
    failed_checks integer,
    error_checks integer
);


ALTER TABLE public.audit_sessions OWNER TO netease;

--
-- Name: audit_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.audit_sessions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.audit_sessions_id_seq OWNER TO netease;

--
-- Name: audit_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.audit_sessions_id_seq OWNED BY public.audit_sessions.id;


--
-- Name: audit_templates; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.audit_templates (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    device_type public.devicetype NOT NULL,
    version character varying(50),
    description text,
    created_at timestamp without time zone,
    user_id integer NOT NULL
);


ALTER TABLE public.audit_templates OWNER TO netease;

--
-- Name: audit_templates_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.audit_templates_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.audit_templates_id_seq OWNER TO netease;

--
-- Name: audit_templates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.audit_templates_id_seq OWNED BY public.audit_templates.id;


--
-- Name: discovery_applications; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.discovery_applications (
    id integer NOT NULL,
    scan_id character varying(50) NOT NULL,
    asset_id integer NOT NULL,
    applied_by_user_id integer,
    ip_address character varying(50),
    fields_applied json,
    applied_at timestamp without time zone
);


ALTER TABLE public.discovery_applications OWNER TO netease;

--
-- Name: COLUMN discovery_applications.scan_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_applications.scan_id IS 'Scan that provided the discovered data';


--
-- Name: COLUMN discovery_applications.asset_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_applications.asset_id IS 'Asset that was updated';


--
-- Name: COLUMN discovery_applications.applied_by_user_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_applications.applied_by_user_id IS 'User who applied the discovery';


--
-- Name: COLUMN discovery_applications.ip_address; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_applications.ip_address IS 'Discovered IP address that was applied';


--
-- Name: COLUMN discovery_applications.fields_applied; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_applications.fields_applied IS 'Fields that were updated with discovered values';


--
-- Name: COLUMN discovery_applications.applied_at; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_applications.applied_at IS 'When discovery was applied';


--
-- Name: discovery_applications_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.discovery_applications_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.discovery_applications_id_seq OWNER TO netease;

--
-- Name: discovery_applications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.discovery_applications_id_seq OWNED BY public.discovery_applications.id;


--
-- Name: discovery_audit_logs; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.discovery_audit_logs (
    id integer NOT NULL,
    user_id integer,
    action character varying(50) NOT NULL,
    scan_id character varying(50),
    asset_id integer,
    ip_address character varying(50),
    target character varying(255),
    details json,
    status character varying(20),
    error_message text,
    "timestamp" timestamp without time zone
);


ALTER TABLE public.discovery_audit_logs OWNER TO netease;

--
-- Name: COLUMN discovery_audit_logs.user_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_audit_logs.user_id IS 'User who performed the action';


--
-- Name: COLUMN discovery_audit_logs.action; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_audit_logs.action IS 'Action type: scan_started, scan_completed, discovery_applied, etc.';


--
-- Name: COLUMN discovery_audit_logs.scan_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_audit_logs.scan_id IS 'Related scan ID';


--
-- Name: COLUMN discovery_audit_logs.asset_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_audit_logs.asset_id IS 'Related asset ID';


--
-- Name: COLUMN discovery_audit_logs.ip_address; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_audit_logs.ip_address IS 'Related IP address';


--
-- Name: COLUMN discovery_audit_logs.target; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_audit_logs.target IS 'Scan target';


--
-- Name: COLUMN discovery_audit_logs.details; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_audit_logs.details IS 'Additional context as JSON';


--
-- Name: COLUMN discovery_audit_logs.status; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_audit_logs.status IS 'Action status: success, failed, warning';


--
-- Name: COLUMN discovery_audit_logs.error_message; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_audit_logs.error_message IS 'Error message if failed';


--
-- Name: COLUMN discovery_audit_logs."timestamp"; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_audit_logs."timestamp" IS 'When the action occurred';


--
-- Name: discovery_audit_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.discovery_audit_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.discovery_audit_logs_id_seq OWNER TO netease;

--
-- Name: discovery_audit_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.discovery_audit_logs_id_seq OWNED BY public.discovery_audit_logs.id;


--
-- Name: discovery_scans; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.discovery_scans (
    id integer NOT NULL,
    scan_id character varying(50) NOT NULL,
    user_id integer NOT NULL,
    target character varying(255) NOT NULL,
    scan_type character varying(20) NOT NULL,
    status character varying(20),
    started_at timestamp without time zone NOT NULL,
    completed_at timestamp without time zone,
    hosts_discovered integer,
    hosts_up integer,
    error_message text,
    results_json json,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


ALTER TABLE public.discovery_scans OWNER TO netease;

--
-- Name: COLUMN discovery_scans.scan_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_scans.scan_id IS 'Unique 8-character scan identifier';


--
-- Name: COLUMN discovery_scans.user_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_scans.user_id IS 'User who initiated the scan';


--
-- Name: COLUMN discovery_scans.target; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_scans.target IS 'Target IP, CIDR range, or IP range';


--
-- Name: COLUMN discovery_scans.scan_type; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_scans.scan_type IS 'Scan intensity: basic, detailed, full';


--
-- Name: COLUMN discovery_scans.status; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_scans.status IS 'Scan status: running, completed, failed';


--
-- Name: COLUMN discovery_scans.started_at; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_scans.started_at IS 'Scan start timestamp';


--
-- Name: COLUMN discovery_scans.completed_at; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_scans.completed_at IS 'Scan completion timestamp';


--
-- Name: COLUMN discovery_scans.hosts_discovered; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_scans.hosts_discovered IS 'Total number of hosts found in scan';


--
-- Name: COLUMN discovery_scans.hosts_up; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_scans.hosts_up IS 'Number of live/responsive hosts';


--
-- Name: COLUMN discovery_scans.error_message; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_scans.error_message IS 'Error details if scan failed';


--
-- Name: COLUMN discovery_scans.results_json; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_scans.results_json IS 'Complete scan results with discovered hosts';


--
-- Name: COLUMN discovery_scans.created_at; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_scans.created_at IS 'Record creation timestamp';


--
-- Name: COLUMN discovery_scans.updated_at; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.discovery_scans.updated_at IS 'Last update timestamp';


--
-- Name: discovery_scans_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.discovery_scans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.discovery_scans_id_seq OWNER TO netease;

--
-- Name: discovery_scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.discovery_scans_id_seq OWNED BY public.discovery_scans.id;


--
-- Name: login_logs; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.login_logs (
    id integer NOT NULL,
    username character varying NOT NULL,
    success boolean NOT NULL,
    ip_address character varying,
    user_agent character varying,
    message character varying,
    "timestamp" timestamp without time zone NOT NULL
);


ALTER TABLE public.login_logs OWNER TO netease;

--
-- Name: login_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.login_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.login_logs_id_seq OWNER TO netease;

--
-- Name: login_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.login_logs_id_seq OWNED BY public.login_logs.id;


--
-- Name: network_zones; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.network_zones (
    id integer NOT NULL,
    zone_name character varying(100) NOT NULL,
    description text
);


ALTER TABLE public.network_zones OWNER TO netease;

--
-- Name: COLUMN network_zones.id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.network_zones.id IS 'Unique identifier';


--
-- Name: COLUMN network_zones.zone_name; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.network_zones.zone_name IS 'Network zone name (e.g., DMZ, Internal, Management)';


--
-- Name: COLUMN network_zones.description; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.network_zones.description IS 'Description of the zone purpose and characteristics';


--
-- Name: network_zones_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.network_zones_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.network_zones_id_seq OWNER TO netease;

--
-- Name: network_zones_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.network_zones_id_seq OWNED BY public.network_zones.id;


--
-- Name: os_catalog; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.os_catalog (
    id integer NOT NULL,
    os_name character varying(100) NOT NULL,
    os_version character varying(50),
    os_family character varying(50),
    description text
);


ALTER TABLE public.os_catalog OWNER TO netease;

--
-- Name: COLUMN os_catalog.id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.os_catalog.id IS 'Unique identifier';


--
-- Name: COLUMN os_catalog.os_name; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.os_catalog.os_name IS 'Operating system name (e.g., Windows Server, Ubuntu, FortiOS)';


--
-- Name: COLUMN os_catalog.os_version; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.os_catalog.os_version IS 'Version information (e.g., 2019, 22.04, 7.2)';


--
-- Name: COLUMN os_catalog.os_family; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.os_catalog.os_family IS 'OS family or category (e.g., Windows, Linux, Network OS)';


--
-- Name: COLUMN os_catalog.description; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.os_catalog.description IS 'Additional information about this OS';


--
-- Name: os_catalog_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.os_catalog_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.os_catalog_id_seq OWNER TO netease;

--
-- Name: os_catalog_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.os_catalog_id_seq OWNED BY public.os_catalog.id;


--
-- Name: user_permissions; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.user_permissions (
    id integer NOT NULL,
    user_id integer NOT NULL,
    module public.moduleenum NOT NULL,
    can_read boolean NOT NULL,
    can_write boolean NOT NULL,
    can_delete boolean NOT NULL
);


ALTER TABLE public.user_permissions OWNER TO netease;

--
-- Name: COLUMN user_permissions.id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.user_permissions.id IS 'Unique identifier for permission record';


--
-- Name: COLUMN user_permissions.user_id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.user_permissions.user_id IS 'Reference to users table';


--
-- Name: COLUMN user_permissions.module; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.user_permissions.module IS 'Which module this permission applies to';


--
-- Name: COLUMN user_permissions.can_read; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.user_permissions.can_read IS 'Can view/read data in this module';


--
-- Name: COLUMN user_permissions.can_write; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.user_permissions.can_write IS 'Can create/edit data in this module';


--
-- Name: COLUMN user_permissions.can_delete; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.user_permissions.can_delete IS 'Can delete data in this module';


--
-- Name: user_permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.user_permissions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.user_permissions_id_seq OWNER TO netease;

--
-- Name: user_permissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.user_permissions_id_seq OWNED BY public.user_permissions.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.users (
    id integer NOT NULL,
    username character varying NOT NULL,
    email character varying,
    hashed_password character varying NOT NULL,
    is_active boolean,
    role public.userrole NOT NULL,
    created_at timestamp without time zone
);


ALTER TABLE public.users OWNER TO netease;

--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.users_id_seq OWNER TO netease;

--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: vendor_catalog; Type: TABLE; Schema: public; Owner: netease
--

CREATE TABLE public.vendor_catalog (
    id integer NOT NULL,
    vendor_name character varying(200) NOT NULL,
    vendor_type character varying(100),
    website character varying(255),
    description text
);


ALTER TABLE public.vendor_catalog OWNER TO netease;

--
-- Name: COLUMN vendor_catalog.id; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.vendor_catalog.id IS 'Unique identifier';


--
-- Name: COLUMN vendor_catalog.vendor_name; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.vendor_catalog.vendor_name IS 'Vendor or manufacturer name (e.g., Cisco, HP, Dell)';


--
-- Name: COLUMN vendor_catalog.vendor_type; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.vendor_catalog.vendor_type IS 'Type of vendor (e.g., Network, Security, Server, Storage)';


--
-- Name: COLUMN vendor_catalog.website; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.vendor_catalog.website IS 'Vendor website URL';


--
-- Name: COLUMN vendor_catalog.description; Type: COMMENT; Schema: public; Owner: netease
--

COMMENT ON COLUMN public.vendor_catalog.description IS 'Additional information about the vendor';


--
-- Name: vendor_catalog_id_seq; Type: SEQUENCE; Schema: public; Owner: netease
--

CREATE SEQUENCE public.vendor_catalog_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.vendor_catalog_id_seq OWNER TO netease;

--
-- Name: vendor_catalog_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: netease
--

ALTER SEQUENCE public.vendor_catalog_id_seq OWNED BY public.vendor_catalog.id;


--
-- Name: asset_dependencies id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_dependencies ALTER COLUMN id SET DEFAULT nextval('public.asset_dependencies_id_seq'::regclass);


--
-- Name: asset_inventory id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_inventory ALTER COLUMN id SET DEFAULT nextval('public.asset_inventory_id_seq'::regclass);


--
-- Name: asset_locations id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_locations ALTER COLUMN id SET DEFAULT nextval('public.asset_locations_id_seq'::regclass);


--
-- Name: asset_owners id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_owners ALTER COLUMN id SET DEFAULT nextval('public.asset_owners_id_seq'::regclass);


--
-- Name: asset_security_status id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_security_status ALTER COLUMN id SET DEFAULT nextval('public.asset_security_status_id_seq'::regclass);


--
-- Name: asset_types id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_types ALTER COLUMN id SET DEFAULT nextval('public.asset_types_id_seq'::regclass);


--
-- Name: audit_checks id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.audit_checks ALTER COLUMN id SET DEFAULT nextval('public.audit_checks_id_seq'::regclass);


--
-- Name: audit_results id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.audit_results ALTER COLUMN id SET DEFAULT nextval('public.audit_results_id_seq'::regclass);


--
-- Name: audit_sessions id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.audit_sessions ALTER COLUMN id SET DEFAULT nextval('public.audit_sessions_id_seq'::regclass);


--
-- Name: audit_templates id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.audit_templates ALTER COLUMN id SET DEFAULT nextval('public.audit_templates_id_seq'::regclass);


--
-- Name: discovery_applications id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.discovery_applications ALTER COLUMN id SET DEFAULT nextval('public.discovery_applications_id_seq'::regclass);


--
-- Name: discovery_audit_logs id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.discovery_audit_logs ALTER COLUMN id SET DEFAULT nextval('public.discovery_audit_logs_id_seq'::regclass);


--
-- Name: discovery_scans id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.discovery_scans ALTER COLUMN id SET DEFAULT nextval('public.discovery_scans_id_seq'::regclass);


--
-- Name: login_logs id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.login_logs ALTER COLUMN id SET DEFAULT nextval('public.login_logs_id_seq'::regclass);


--
-- Name: network_zones id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.network_zones ALTER COLUMN id SET DEFAULT nextval('public.network_zones_id_seq'::regclass);


--
-- Name: os_catalog id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.os_catalog ALTER COLUMN id SET DEFAULT nextval('public.os_catalog_id_seq'::regclass);


--
-- Name: user_permissions id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.user_permissions ALTER COLUMN id SET DEFAULT nextval('public.user_permissions_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: vendor_catalog id; Type: DEFAULT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.vendor_catalog ALTER COLUMN id SET DEFAULT nextval('public.vendor_catalog_id_seq'::regclass);


--
-- Data for Name: alembic_version; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.alembic_version (version_num) FROM stdin;
e4de134c385b
\.


--
-- Data for Name: asset_dependencies; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.asset_dependencies (id, asset_id, depends_on_id, relation_type, description) FROM stdin;
1	30	31	NETWORK_LINK	Core switch uplinks to Edge firewall
\.


--
-- Data for Name: asset_inventory; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.asset_inventory (id, asset_name, hostname, asset_type_id, asset_role, manufacturer, model, serial_number, os_name, os_version, ip_address, mac_address, location_id, owner_id, status, confidentiality_level, risk_level, last_audit_date, last_patch_date, asset_value, description, user_id, created_at, updated_at, discovered_fields) FROM stdin;
25	ali	12	7	\N	a	a	a	\N	\N	AAA	AAA	2	\N	ACTIVE	\N	\N	\N	\N	\N	a	1	2025-11-29 15:30:20.343538	2025-11-30 16:42:54.634042	{}
26	Sina-19	localhost	8	Core	test	test	12345	Arch	12.54	192.168.100.1	AA:BB:BB:CC	1	3	STANDBY	PUBLIC	HIGH	2025-11-30	2025-11-30	3.00	saddsfs	1	2025-11-30 16:48:58.450379	2025-11-30 16:48:58.450384	{}
29	sina		3					linux		192.168.1.1		2	3	ACTIVE	PUBLIC	MEDIUM	2025-12-02	2025-12-02	66.00		1	2025-12-02 14:46:04.751003	2025-12-02 14:46:04.751007	{}
5	asset test	local	6	\N	Cisco	x	23	artix	23	192.168.1.1	asdsad	1	\N	ACTIVE	\N	\N	\N	\N	\N	\N	1	2025-11-24 18:01:29.352207	2025-12-04 10:46:11.970767	{}
30	DC1-CSW01	DC1-CSW01	4	Core Switch	Cisco	Catalyst 9300	UUID-EXAMPLE-1	IOS-XE	17.9.3	10.0.0.10	00:11:22:33:44:55	\N	\N	ACTIVE	\N	\N	\N	\N	\N	Core switch for DC1 aggregation	1	2025-12-06 15:07:18.637165	2025-12-06 15:07:18.637169	{}
31	DC1-FW01	DC1-FW01	1	Edge Firewall	Cisco	Firepower 2100	UUID-EXAMPLE-2	FTD	7.2.0	10.0.0.1	\N	\N	\N	ACTIVE	\N	\N	\N	\N	\N	Edge firewall for DC1 perimeter security	1	2025-12-06 15:08:30.633542	2025-12-06 15:08:30.633547	{}
\.


--
-- Data for Name: asset_locations; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.asset_locations (id, site_name, rack_name, room, floor, network_zone, vlan_id, subnet, description, user_id) FROM stdin;
1	Main DC	Rack-12	\N	\N	DMZ	\N	\N	\N	1
2	Main Data Center	Rack 2	\N	\N	DMZ	\N	\N	\N	1
\.


--
-- Data for Name: asset_owners; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.asset_owners (id, full_name, department, role, email, phone, responsibility_level, user_id, created_at) FROM stdin;
3	Sina Bimesl	Backend	\N	sina@gmail.com	\N	\N	1	2025-11-24 18:00:08.155293
4	Ahad Zargar	UI Design	\N	ahad_designer@gmail.com	\N	\N	1	2025-11-25 11:09:07.764686
5	Ali mansori	front	dev	\N	\N	\N	1	2025-12-04 11:03:53.158306
\.


--
-- Data for Name: asset_security_status; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.asset_security_status (id, asset_id, antivirus_installed, antivirus_status, firewall_enabled, last_patch_date, backup_enabled, vulnerability_score, compliance_status, notes) FROM stdin;
\.


--
-- Data for Name: asset_types; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.asset_types (id, type_name, category, description) FROM stdin;
1	Firewall	Security	Network security device
3	Router	Network	\N
4	Switch	Network	\N
5	Server	Infrastructure	\N
6	Endpoint	Client	\N
7	Access Point	Network	\N
8	Storage	Infrastructure	\N
9	Application	Application	\N
10	Database	Application	\N
11	Security Appliance	Security	\N
12	string	string	string
\.


--
-- Data for Name: audit_checks; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.audit_checks (id, template_id, check_number, title, description, command, expected_output, severity) FROM stdin;
\.


--
-- Data for Name: audit_results; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.audit_results (id, session_id, check_id, status, actual_output, error_message, checked_at) FROM stdin;
\.


--
-- Data for Name: audit_sessions; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.audit_sessions (id, template_id, user_id, asset_id, target_ip, device_type, started_at, completed_at, status, total_checks, passed_checks, failed_checks, error_checks) FROM stdin;
\.


--
-- Data for Name: audit_templates; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.audit_templates (id, name, device_type, version, description, created_at, user_id) FROM stdin;
\.


--
-- Data for Name: discovery_applications; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.discovery_applications (id, scan_id, asset_id, applied_by_user_id, ip_address, fields_applied, applied_at) FROM stdin;
\.


--
-- Data for Name: discovery_audit_logs; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.discovery_audit_logs (id, user_id, action, scan_id, asset_id, ip_address, target, details, status, error_message, "timestamp") FROM stdin;
\.


--
-- Data for Name: discovery_scans; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.discovery_scans (id, scan_id, user_id, target, scan_type, status, started_at, completed_at, hosts_discovered, hosts_up, error_message, results_json, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: login_logs; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.login_logs (id, username, success, ip_address, user_agent, message, "timestamp") FROM stdin;
1	admin	t	127.0.0.1	curl/8.17.0	Login successfully with admin Role.	2025-11-24 17:57:19.953766
2	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-24 17:59:41.419531
3	admin	t	127.0.0.1	curl/8.17.0	Login successfully with admin Role.	2025-11-25 10:39:05.915936
4	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-25 11:00:49.770863
5	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-25 11:02:07.277473
6	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-25 11:08:36.844308
7	admin	f	127.0.0.1	curl/8.17.0	Incorrect username or password	2025-11-25 18:08:14.114183
8	admin	t	127.0.0.1	curl/8.17.0	Login successfully with admin Role.	2025-11-25 18:08:46.027456
9	admin	t	127.0.0.1	curl/8.17.0	Login successfully with admin Role.	2025-11-25 18:11:54.171134
10	testuser	t	127.0.0.1	curl/8.17.0	Login successfully with user Role.	2025-11-25 18:15:27.376309
11	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-25 18:36:29.750738
12	admin	f	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Incorrect username or password	2025-11-25 18:36:51.059392
13	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-25 18:36:55.648378
14	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-25 18:42:34.712881
15	testuser	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with user Role.	2025-11-26 10:44:06.205992
16	admin	f	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Incorrect username or password	2025-11-26 10:44:25.65888
17	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-26 10:44:33.770667
18	testuser	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with user Role.	2025-11-26 11:13:23.61922
19	ada	f	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Incorrect username or password	2025-11-26 11:16:53.949392
20	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-26 11:17:00.511002
21	ali	f	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Incorrect username or password	2025-11-26 11:24:30.619384
22	ali	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with guest Role.	2025-11-26 11:24:32.261748
23	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-26 11:35:55.067486
24	ali	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with guest Role.	2025-11-26 11:37:13.981979
25	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-26 11:37:37.180123
26	ahad	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with manager Role.	2025-11-26 11:38:27.420841
27	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-26 11:56:22.40256
28	testuser	f	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Incorrect username or password	2025-11-26 12:00:56.501842
29	testuser	f	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Incorrect username or password	2025-11-26 12:01:01.32969
30	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-26 12:01:07.625988
31	admin	f	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Incorrect username or password	2025-11-26 12:04:42.717039
32	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-26 12:04:45.429612
33	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-26 12:07:04.958493
34	admin	t	127.0.0.1	curl/8.17.0	Login successfully with admin Role.	2025-11-26 12:07:47.425289
35	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-26 12:10:34.005016
36	admin	f	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Incorrect username or password	2025-11-26 12:47:26.744344
37	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-26 12:47:29.356538
38	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-26 13:04:45.70026
39	admin	f	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Incorrect username or password	2025-11-26 14:04:13.443985
40	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-26 14:04:16.603309
41	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-27 19:20:43.533945
42	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-27 19:27:04.283856
43	ahad	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with manager Role.	2025-11-27 19:27:52.568427
44	ali	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with guest Role.	2025-11-27 19:28:08.57264
45	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-27 19:28:25.939923
46	ali	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with guest Role.	2025-11-27 19:29:05.163871
47	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-27 19:29:29.724402
48	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-29 12:55:52.740632
49	asdsada	f	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Incorrect username or password	2025-11-29 12:56:04.563827
50	ahad	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with manager Role.	2025-11-29 12:56:19.310855
51	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-29 12:56:30.642379
52	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-29 13:38:08.030626
53	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-29 14:13:06.8334
54	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-29 14:30:47.129765
55	aylar	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with manager Role.	2025-11-29 14:31:33.533005
56	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-29 14:31:51.209624
57	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-29 15:27:33.325778
58	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-29 16:17:32.823568
59	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-29 17:10:29.198441
60	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-29 17:18:50.927689
61	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-29 18:09:19.241855
62	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-30 16:37:09.795896
63	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-30 16:38:11.662157
64	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-30 17:12:50.245846
65	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-30 17:13:56.130697
66	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-30 17:59:03.477519
67	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-30 18:26:07.677116
68	ahad	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with manager Role.	2025-11-30 18:27:21.948695
69	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-30 18:27:33.27839
70	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-30 18:42:23.43093
71	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-30 18:53:47.405021
72	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-30 19:09:20.017078
73	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-30 19:10:55.82826
74	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-30 19:22:00.837262
75	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-30 19:24:35.325808
76	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-11-30 20:10:56.546884
77	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-01 10:24:16.592354
78	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-01 11:26:09.495207
79	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-01 11:27:01.818269
80	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-01 11:48:14.240063
81	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-01 12:15:27.686258
82	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-01 12:20:20.33051
83	admin	t	127.0.0.1	curl/8.17.0	Login successfully with admin Role.	2025-12-01 12:21:13.548518
84	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-01 13:27:56.450106
85	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-01 13:33:46.026276
86	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-01 13:40:28.87167
87	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-01 13:47:57.88456
88	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-01 13:49:56.295861
89	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-01 16:51:25.315274
90	admin	t	127.0.0.1	curl/8.17.0	Login successfully with admin Role.	2025-12-01 16:52:25.358654
91	admin	t	127.0.0.1	curl/8.17.0	Login successfully with admin Role.	2025-12-01 19:49:41.108456
92	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-01 19:51:09.227398
93	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-01 20:31:29.466185
94	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-02 12:21:48.375877
95	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-02 13:11:52.516896
96	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-02 13:42:53.001941
97	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-02 14:03:36.44296
98	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-02 14:04:24.985796
99	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-02 14:34:55.868793
100	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-02 15:05:36.951116
101	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-02 16:38:02.120158
102	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-02 17:09:00.705189
103	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-02 17:39:57.048456
104	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-02 18:44:19.800154
105	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-03 10:44:05.975583
106	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-03 18:48:28.447956
107	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-03 18:57:49.802284
108	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-04 09:33:08.393362
109	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-04 10:11:43.651182
110	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-04 10:24:32.844968
111	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-04 10:55:27.322344
112	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-04 11:26:13.05862
113	sina	f	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Incorrect username or password	2025-12-04 15:36:59.388624
114	ahad	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with manager Role.	2025-12-04 15:37:03.375248
115	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-04 15:37:20.040921
116	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-04 16:15:34.902599
117	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-04 17:41:40.917658
118	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-04 18:19:33.24289
119	ad,o	f	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Incorrect username or password	2025-12-04 19:08:14.895859
120	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-04 19:08:19.422399
121	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-05 16:28:19.469375
122	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-05 17:12:51.407327
123	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-05 18:20:19.293108
124	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-05 19:01:36.573317
125	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-06 11:07:24.81056
126	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-06 15:10:06.160017
127	super-user	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-06 15:16:42.817114
128	admin	t	127.0.0.1	Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	Login successfully with admin Role.	2025-12-07 11:59:29.28652
\.


--
-- Data for Name: network_zones; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.network_zones (id, zone_name, description) FROM stdin;
1	DMZ	\N
2	Internal	\N
3	Management	\N
4	Guest	\N
5	External	\N
\.


--
-- Data for Name: os_catalog; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.os_catalog (id, os_name, os_version, os_family, description) FROM stdin;
1	Windows Server	2019	Windows	\N
2	Ubuntu	22.04	Linux	\N
3	FortiOS	7.2	Network OS	\N
4	Debian	\N	\N	\N
5	Arch Linux	\N	\N	\N
6	Open BSD	\N	\N	\N
\.


--
-- Data for Name: user_permissions; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.user_permissions (id, user_id, module, can_read, can_write, can_delete) FROM stdin;
27	5	DASHBOARD	t	f	f
28	5	ASSET_REQUIREMENT	t	f	f
29	5	ASSET_LIST	f	f	f
30	5	ASSET_AUTO_DISCOVERY	f	f	f
31	5	USER_MANAGEMENT	t	f	f
32	5	AUDITING	f	f	f
33	5	HARDENING	f	f	f
34	5	LOGS	t	f	f
35	3	DASHBOARD	t	f	f
36	3	ASSET_REQUIREMENT	f	f	f
37	3	ASSET_LIST	t	t	f
38	3	ASSET_AUTO_DISCOVERY	f	f	f
39	3	USER_MANAGEMENT	f	f	f
40	3	AUDITING	f	f	f
41	3	HARDENING	f	f	f
42	3	LOGS	f	f	f
67	4	DASHBOARD	f	f	f
68	4	ASSET_REQUIREMENT	t	f	f
69	4	ASSET_LIST	t	t	t
70	4	ASSET_AUTO_DISCOVERY	f	f	f
71	4	USER_MANAGEMENT	f	f	f
72	4	AUDITING	f	f	f
73	4	HARDENING	f	f	f
74	4	LOGS	f	f	f
75	6	DASHBOARD	t	t	t
76	6	ASSET_REQUIREMENT	t	t	t
77	6	ASSET_LIST	t	t	t
78	6	ASSET_AUTO_DISCOVERY	f	f	f
79	6	USER_MANAGEMENT	f	f	t
80	6	AUDITING	f	f	f
81	6	HARDENING	f	f	f
82	6	LOGS	f	f	f
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.users (id, username, email, hashed_password, is_active, role, created_at) FROM stdin;
1	admin	admin@test.com	$2b$12$IipZH2zL8hj4i9q6JMyclOVrtAYl9xOJdCzALgMLa/9PpcAJDg4Gi	t	ADMIN	2025-11-24 13:48:05.499671
5	ahad	ahad@gmail.com	$2b$12$fyScKE1ioLeU/qCVtQrmsu9oONE61C.skEz0DRDMrY5W4SXzB1xfG	t	MANAGER	2025-11-26 11:38:19.804933
3	testuser	test@example.com	$2b$12$A2X7kAU.tXiVTWebxGpD0OmnWkJ4yX3p/62oiKlKrG9M8wg3LskZe	f	USER	2025-11-25 18:14:21.210361
4	ali	ali@gmail.com	$2b$12$88WIthpxjjkj5p6FhMC8Te5.8LdEjSZGhGK5QpRBfgJRKjEv.aEr.	f	USER	2025-11-26 11:18:36.268186
6	aylar	rezyi@gmail.com	$2b$12$8qcWLkoKu3H6I77SM614gua9kNbwfYhZtsZMpNfOtG3jNLE0h/Kyi	t	MANAGER	2025-11-29 14:31:25.824792
7	super-user	admin@gmail.com	$2b$12$Mrk/gCs1h3v7ndD83qtU/uFZ.ePUV.h6E4uTy95XRI/YeBjDy5YQC	t	ADMIN	2025-12-06 15:16:33.2132
\.


--
-- Data for Name: vendor_catalog; Type: TABLE DATA; Schema: public; Owner: netease
--

COPY public.vendor_catalog (id, vendor_name, vendor_type, website, description) FROM stdin;
1	Cisco	Network	\N	\N
2	HP	Server	\N	\N
3	Fortinet	Security	\N	\N
\.


--
-- Name: asset_dependencies_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.asset_dependencies_id_seq', 1, true);


--
-- Name: asset_inventory_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.asset_inventory_id_seq', 31, true);


--
-- Name: asset_locations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.asset_locations_id_seq', 3, true);


--
-- Name: asset_owners_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.asset_owners_id_seq', 5, true);


--
-- Name: asset_security_status_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.asset_security_status_id_seq', 1, false);


--
-- Name: asset_types_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.asset_types_id_seq', 14, true);


--
-- Name: audit_checks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.audit_checks_id_seq', 1, false);


--
-- Name: audit_results_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.audit_results_id_seq', 1, false);


--
-- Name: audit_sessions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.audit_sessions_id_seq', 1, false);


--
-- Name: audit_templates_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.audit_templates_id_seq', 1, false);


--
-- Name: discovery_applications_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.discovery_applications_id_seq', 1, false);


--
-- Name: discovery_audit_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.discovery_audit_logs_id_seq', 1, false);


--
-- Name: discovery_scans_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.discovery_scans_id_seq', 1, false);


--
-- Name: login_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.login_logs_id_seq', 128, true);


--
-- Name: network_zones_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.network_zones_id_seq', 5, true);


--
-- Name: os_catalog_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.os_catalog_id_seq', 6, true);


--
-- Name: user_permissions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.user_permissions_id_seq', 82, true);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.users_id_seq', 7, true);


--
-- Name: vendor_catalog_id_seq; Type: SEQUENCE SET; Schema: public; Owner: netease
--

SELECT pg_catalog.setval('public.vendor_catalog_id_seq', 4, true);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: asset_dependencies asset_dependencies_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_dependencies
    ADD CONSTRAINT asset_dependencies_pkey PRIMARY KEY (id);


--
-- Name: asset_inventory asset_inventory_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_inventory
    ADD CONSTRAINT asset_inventory_pkey PRIMARY KEY (id);


--
-- Name: asset_locations asset_locations_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_locations
    ADD CONSTRAINT asset_locations_pkey PRIMARY KEY (id);


--
-- Name: asset_owners asset_owners_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_owners
    ADD CONSTRAINT asset_owners_pkey PRIMARY KEY (id);


--
-- Name: asset_security_status asset_security_status_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_security_status
    ADD CONSTRAINT asset_security_status_pkey PRIMARY KEY (id);


--
-- Name: asset_types asset_types_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_types
    ADD CONSTRAINT asset_types_pkey PRIMARY KEY (id);


--
-- Name: audit_checks audit_checks_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.audit_checks
    ADD CONSTRAINT audit_checks_pkey PRIMARY KEY (id);


--
-- Name: audit_results audit_results_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.audit_results
    ADD CONSTRAINT audit_results_pkey PRIMARY KEY (id);


--
-- Name: audit_sessions audit_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.audit_sessions
    ADD CONSTRAINT audit_sessions_pkey PRIMARY KEY (id);


--
-- Name: audit_templates audit_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.audit_templates
    ADD CONSTRAINT audit_templates_pkey PRIMARY KEY (id);


--
-- Name: discovery_applications discovery_applications_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.discovery_applications
    ADD CONSTRAINT discovery_applications_pkey PRIMARY KEY (id);


--
-- Name: discovery_audit_logs discovery_audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.discovery_audit_logs
    ADD CONSTRAINT discovery_audit_logs_pkey PRIMARY KEY (id);


--
-- Name: discovery_scans discovery_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.discovery_scans
    ADD CONSTRAINT discovery_scans_pkey PRIMARY KEY (id);


--
-- Name: login_logs login_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.login_logs
    ADD CONSTRAINT login_logs_pkey PRIMARY KEY (id);


--
-- Name: network_zones network_zones_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.network_zones
    ADD CONSTRAINT network_zones_pkey PRIMARY KEY (id);


--
-- Name: os_catalog os_catalog_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.os_catalog
    ADD CONSTRAINT os_catalog_pkey PRIMARY KEY (id);


--
-- Name: user_permissions unique_user_module; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.user_permissions
    ADD CONSTRAINT unique_user_module UNIQUE (user_id, module);


--
-- Name: user_permissions user_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.user_permissions
    ADD CONSTRAINT user_permissions_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: vendor_catalog vendor_catalog_pkey; Type: CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.vendor_catalog
    ADD CONSTRAINT vendor_catalog_pkey PRIMARY KEY (id);


--
-- Name: ix_asset_dependencies_asset_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_dependencies_asset_id ON public.asset_dependencies USING btree (asset_id);


--
-- Name: ix_asset_dependencies_depends_on_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_dependencies_depends_on_id ON public.asset_dependencies USING btree (depends_on_id);


--
-- Name: ix_asset_dependencies_relation_type; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_dependencies_relation_type ON public.asset_dependencies USING btree (relation_type);


--
-- Name: ix_asset_inventory_asset_name; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_inventory_asset_name ON public.asset_inventory USING btree (asset_name);


--
-- Name: ix_asset_inventory_asset_type_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_inventory_asset_type_id ON public.asset_inventory USING btree (asset_type_id);


--
-- Name: ix_asset_inventory_confidentiality_level; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_inventory_confidentiality_level ON public.asset_inventory USING btree (confidentiality_level);


--
-- Name: ix_asset_inventory_hostname; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_inventory_hostname ON public.asset_inventory USING btree (hostname);


--
-- Name: ix_asset_inventory_ip_address; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_inventory_ip_address ON public.asset_inventory USING btree (ip_address);


--
-- Name: ix_asset_inventory_location_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_inventory_location_id ON public.asset_inventory USING btree (location_id);


--
-- Name: ix_asset_inventory_mac_address; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_inventory_mac_address ON public.asset_inventory USING btree (mac_address);


--
-- Name: ix_asset_inventory_manufacturer; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_inventory_manufacturer ON public.asset_inventory USING btree (manufacturer);


--
-- Name: ix_asset_inventory_os_name; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_inventory_os_name ON public.asset_inventory USING btree (os_name);


--
-- Name: ix_asset_inventory_owner_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_inventory_owner_id ON public.asset_inventory USING btree (owner_id);


--
-- Name: ix_asset_inventory_risk_level; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_inventory_risk_level ON public.asset_inventory USING btree (risk_level);


--
-- Name: ix_asset_inventory_serial_number; Type: INDEX; Schema: public; Owner: netease
--

CREATE UNIQUE INDEX ix_asset_inventory_serial_number ON public.asset_inventory USING btree (serial_number);


--
-- Name: ix_asset_inventory_status; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_inventory_status ON public.asset_inventory USING btree (status);


--
-- Name: ix_asset_inventory_user_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_inventory_user_id ON public.asset_inventory USING btree (user_id);


--
-- Name: ix_asset_locations_network_zone; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_locations_network_zone ON public.asset_locations USING btree (network_zone);


--
-- Name: ix_asset_locations_site_name; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_locations_site_name ON public.asset_locations USING btree (site_name);


--
-- Name: ix_asset_locations_user_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_locations_user_id ON public.asset_locations USING btree (user_id);


--
-- Name: ix_asset_owners_department; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_owners_department ON public.asset_owners USING btree (department);


--
-- Name: ix_asset_owners_email; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_owners_email ON public.asset_owners USING btree (email);


--
-- Name: ix_asset_owners_full_name; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_owners_full_name ON public.asset_owners USING btree (full_name);


--
-- Name: ix_asset_owners_user_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_owners_user_id ON public.asset_owners USING btree (user_id);


--
-- Name: ix_asset_security_status_asset_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE UNIQUE INDEX ix_asset_security_status_asset_id ON public.asset_security_status USING btree (asset_id);


--
-- Name: ix_asset_security_status_compliance_status; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_security_status_compliance_status ON public.asset_security_status USING btree (compliance_status);


--
-- Name: ix_asset_types_category; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_asset_types_category ON public.asset_types USING btree (category);


--
-- Name: ix_asset_types_type_name; Type: INDEX; Schema: public; Owner: netease
--

CREATE UNIQUE INDEX ix_asset_types_type_name ON public.asset_types USING btree (type_name);


--
-- Name: ix_audit_checks_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_audit_checks_id ON public.audit_checks USING btree (id);


--
-- Name: ix_audit_results_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_audit_results_id ON public.audit_results USING btree (id);


--
-- Name: ix_audit_sessions_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_audit_sessions_id ON public.audit_sessions USING btree (id);


--
-- Name: ix_audit_templates_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_audit_templates_id ON public.audit_templates USING btree (id);


--
-- Name: ix_discovery_applications_applied_at; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_discovery_applications_applied_at ON public.discovery_applications USING btree (applied_at);


--
-- Name: ix_discovery_applications_applied_by_user_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_discovery_applications_applied_by_user_id ON public.discovery_applications USING btree (applied_by_user_id);


--
-- Name: ix_discovery_applications_asset_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_discovery_applications_asset_id ON public.discovery_applications USING btree (asset_id);


--
-- Name: ix_discovery_applications_scan_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_discovery_applications_scan_id ON public.discovery_applications USING btree (scan_id);


--
-- Name: ix_discovery_audit_logs_action; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_discovery_audit_logs_action ON public.discovery_audit_logs USING btree (action);


--
-- Name: ix_discovery_audit_logs_asset_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_discovery_audit_logs_asset_id ON public.discovery_audit_logs USING btree (asset_id);


--
-- Name: ix_discovery_audit_logs_scan_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_discovery_audit_logs_scan_id ON public.discovery_audit_logs USING btree (scan_id);


--
-- Name: ix_discovery_audit_logs_timestamp; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_discovery_audit_logs_timestamp ON public.discovery_audit_logs USING btree ("timestamp");


--
-- Name: ix_discovery_audit_logs_user_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_discovery_audit_logs_user_id ON public.discovery_audit_logs USING btree (user_id);


--
-- Name: ix_discovery_scans_scan_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE UNIQUE INDEX ix_discovery_scans_scan_id ON public.discovery_scans USING btree (scan_id);


--
-- Name: ix_discovery_scans_started_at; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_discovery_scans_started_at ON public.discovery_scans USING btree (started_at);


--
-- Name: ix_discovery_scans_status; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_discovery_scans_status ON public.discovery_scans USING btree (status);


--
-- Name: ix_discovery_scans_target; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_discovery_scans_target ON public.discovery_scans USING btree (target);


--
-- Name: ix_discovery_scans_user_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_discovery_scans_user_id ON public.discovery_scans USING btree (user_id);


--
-- Name: ix_login_logs_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_login_logs_id ON public.login_logs USING btree (id);


--
-- Name: ix_login_logs_username; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_login_logs_username ON public.login_logs USING btree (username);


--
-- Name: ix_network_zones_zone_name; Type: INDEX; Schema: public; Owner: netease
--

CREATE UNIQUE INDEX ix_network_zones_zone_name ON public.network_zones USING btree (zone_name);


--
-- Name: ix_os_catalog_os_family; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_os_catalog_os_family ON public.os_catalog USING btree (os_family);


--
-- Name: ix_os_catalog_os_name; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_os_catalog_os_name ON public.os_catalog USING btree (os_name);


--
-- Name: ix_user_permissions_module; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_user_permissions_module ON public.user_permissions USING btree (module);


--
-- Name: ix_user_permissions_user_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_user_permissions_user_id ON public.user_permissions USING btree (user_id);


--
-- Name: ix_users_email; Type: INDEX; Schema: public; Owner: netease
--

CREATE UNIQUE INDEX ix_users_email ON public.users USING btree (email);


--
-- Name: ix_users_id; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_users_id ON public.users USING btree (id);


--
-- Name: ix_users_username; Type: INDEX; Schema: public; Owner: netease
--

CREATE UNIQUE INDEX ix_users_username ON public.users USING btree (username);


--
-- Name: ix_vendor_catalog_vendor_name; Type: INDEX; Schema: public; Owner: netease
--

CREATE UNIQUE INDEX ix_vendor_catalog_vendor_name ON public.vendor_catalog USING btree (vendor_name);


--
-- Name: ix_vendor_catalog_vendor_type; Type: INDEX; Schema: public; Owner: netease
--

CREATE INDEX ix_vendor_catalog_vendor_type ON public.vendor_catalog USING btree (vendor_type);


--
-- Name: asset_dependencies asset_dependencies_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_dependencies
    ADD CONSTRAINT asset_dependencies_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.asset_inventory(id) ON DELETE CASCADE;


--
-- Name: asset_dependencies asset_dependencies_depends_on_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_dependencies
    ADD CONSTRAINT asset_dependencies_depends_on_id_fkey FOREIGN KEY (depends_on_id) REFERENCES public.asset_inventory(id) ON DELETE CASCADE;


--
-- Name: asset_inventory asset_inventory_asset_type_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_inventory
    ADD CONSTRAINT asset_inventory_asset_type_id_fkey FOREIGN KEY (asset_type_id) REFERENCES public.asset_types(id) ON DELETE RESTRICT;


--
-- Name: asset_inventory asset_inventory_location_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_inventory
    ADD CONSTRAINT asset_inventory_location_id_fkey FOREIGN KEY (location_id) REFERENCES public.asset_locations(id) ON DELETE SET NULL;


--
-- Name: asset_inventory asset_inventory_owner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_inventory
    ADD CONSTRAINT asset_inventory_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public.asset_owners(id) ON DELETE SET NULL;


--
-- Name: asset_inventory asset_inventory_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_inventory
    ADD CONSTRAINT asset_inventory_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: asset_locations asset_locations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_locations
    ADD CONSTRAINT asset_locations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: asset_owners asset_owners_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_owners
    ADD CONSTRAINT asset_owners_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: asset_security_status asset_security_status_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.asset_security_status
    ADD CONSTRAINT asset_security_status_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.asset_inventory(id) ON DELETE CASCADE;


--
-- Name: audit_checks audit_checks_template_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.audit_checks
    ADD CONSTRAINT audit_checks_template_id_fkey FOREIGN KEY (template_id) REFERENCES public.audit_templates(id);


--
-- Name: audit_results audit_results_check_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.audit_results
    ADD CONSTRAINT audit_results_check_id_fkey FOREIGN KEY (check_id) REFERENCES public.audit_checks(id);


--
-- Name: audit_results audit_results_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.audit_results
    ADD CONSTRAINT audit_results_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.audit_sessions(id);


--
-- Name: audit_sessions audit_sessions_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.audit_sessions
    ADD CONSTRAINT audit_sessions_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.asset_inventory(id);


--
-- Name: audit_sessions audit_sessions_template_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.audit_sessions
    ADD CONSTRAINT audit_sessions_template_id_fkey FOREIGN KEY (template_id) REFERENCES public.audit_templates(id);


--
-- Name: audit_sessions audit_sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.audit_sessions
    ADD CONSTRAINT audit_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: audit_templates audit_templates_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.audit_templates
    ADD CONSTRAINT audit_templates_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: discovery_applications discovery_applications_applied_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.discovery_applications
    ADD CONSTRAINT discovery_applications_applied_by_user_id_fkey FOREIGN KEY (applied_by_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: discovery_applications discovery_applications_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.discovery_applications
    ADD CONSTRAINT discovery_applications_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.asset_inventory(id) ON DELETE CASCADE;


--
-- Name: discovery_applications discovery_applications_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.discovery_applications
    ADD CONSTRAINT discovery_applications_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.discovery_scans(scan_id) ON DELETE CASCADE;


--
-- Name: discovery_audit_logs discovery_audit_logs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.discovery_audit_logs
    ADD CONSTRAINT discovery_audit_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: discovery_scans discovery_scans_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.discovery_scans
    ADD CONSTRAINT discovery_scans_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_permissions user_permissions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: netease
--

ALTER TABLE ONLY public.user_permissions
    ADD CONSTRAINT user_permissions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: pg_database_owner
--

GRANT ALL ON SCHEMA public TO netease;


--
-- Name: DEFAULT PRIVILEGES FOR SEQUENCES; Type: DEFAULT ACL; Schema: public; Owner: postgres
--

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON SEQUENCES TO netease;


--
-- Name: DEFAULT PRIVILEGES FOR TABLES; Type: DEFAULT ACL; Schema: public; Owner: postgres
--

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON TABLES TO netease;


--
-- PostgreSQL database dump complete
--

\unrestrict kaDBH2avjay1CyWOhZXouxomLe2lGugDemT4VOaudCMVDfKGYNbXe8Aw4rvIGUP


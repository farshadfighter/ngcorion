/**
 * Default WinRM listener port for Windows Server auditing and hardening.
 *
 * 5985 is the WinRM HTTP listener Windows enables by default; 5986 is the
 * optional HTTPS listener and stays selectable by typing it into the port
 * field. Mirrors DEFAULT_WINRM_PORT in app/modules/windows/winrm_endpoint.py —
 * keep the two in step.
 */
export const DEFAULT_WINRM_PORT = "5985";

export default DEFAULT_WINRM_PORT;

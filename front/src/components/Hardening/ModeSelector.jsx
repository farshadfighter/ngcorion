/**
 * ModeSelector - Select hardening mode and device type
 */

const ModeSelector = ({
    onSelect,
    loading = false,
    supportedDevices = [],
}) => {
    return (
        <div className="mode-selector">
            <h3>Select Hardening Mode</h3>
            <p className="mode-description">
                Choose how you want to perform device hardening.
            </p>

            <div className="mode-cards">
                {/* Post-Audit Mode */}
                <div className="mode-card">
                    <div className="mode-card-icon">🔍</div>
                    <h4>Post-Audit Hardening</h4>
                    <p>
                        Fix failed checks from a completed audit session.
                        Only controls related to failed checks will be shown.
                    </p>
                    <ul className="mode-features">
                        <li>Based on audit results</li>
                        <li>Targeted fixes only</li>
                        <li>Session-linked execution</li>
                    </ul>
                    <button
                        className="btn btn-primary"
                        onClick={() => onSelect('post_audit')}
                        disabled={loading}
                    >
                        Select Audit Session
                    </button>
                </div>

                {/* Full Hardening Mode */}
                <div className="mode-card">
                    <div className="mode-card-icon">🛡️</div>
                    <h4>Full Hardening</h4>
                    <p>
                        Apply all CIS controls to a device without prior audit.
                        Choose which controls to SKIP, AUDIT, or APPLY.
                    </p>
                    <ul className="mode-features">
                        <li>All CIS controls available</li>
                        <li>Flexible state per control</li>
                        <li>Direct device connection</li>
                    </ul>

                    <div className="device-selection">
                        <label>Select Device Type:</label>
                        <div className="device-buttons">
                            {supportedDevices.map(device => (
                                <button
                                    key={device.type}
                                    className={`btn ${device.status === 'available' ? 'btn-primary' : 'btn-disabled'}`}
                                    onClick={() => device.status === 'available' && onSelect('full', device.type)}
                                    disabled={loading || device.status !== 'available'}
                                    title={device.status !== 'available' ? 'Coming soon' : device.name}
                                >
                                    {device.name}
                                    {device.status !== 'available' && (
                                        <span className="coming-soon-badge">Soon</span>
                                    )}
                                </button>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ModeSelector;

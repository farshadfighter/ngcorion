import { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchEnums } from "../../store/requirementSlice";

export const OthersTab = () => {
    const dispatch = useDispatch();
    const { enums, isLoading } = useSelector((state) => state.requirements);

    useEffect(() => {
        dispatch(fetchEnums());
    }, [dispatch]);

    if (isLoading) {
        return <div className="loading-spinner">Loading...</div>;
    }

    // Extract values
    let statusValues = [];
    let confidentialityValues = [];
    let riskValues = [];

    if (enums && enums.status && Array.isArray(enums.status)) {
        statusValues = enums.status.map(item => {
            if (typeof item === 'object' && item.value) return item.value;
            return item;
        });
    }

    if (enums && enums.confidentiality && Array.isArray(enums.confidentiality)) {
        confidentialityValues = enums.confidentiality.map(item => {
            if (typeof item === 'object' && item.value) return item.value;
            return item;
        });
    }

    if (enums && enums.risk && Array.isArray(enums.risk)) {
        riskValues = enums.risk.map(item => {
            if (typeof item === 'object' && item.value) return item.value;
            return item;
        });
    }

    return (
        <div className="tab-content">
            <div className="enum-info">
                <p>ℹ️ These are system-defined values. They cannot be modified.</p>
            </div>

            {/* Status Section */}
            <div className="others-section">
                <h3 className="section-title">Status</h3>
                <div className="table-container">
                    <table className="requirement-table">
                        <thead>
                        <tr>
                            <th>ID</th>
                            <th>Value</th>
                            <th>Display Name</th>
                        </tr>
                        </thead>
                        <tbody>
                        {statusValues.length === 0 ? (
                            <tr>
                                <td colSpan="3" className="no-data">
                                    No status values found
                                </td>
                            </tr>
                        ) : (
                            statusValues.map((value, index) => (
                                <tr key={index}>
                                    <td>{index + 1}</td>
                                    <td>{value}</td>
                                    <td>{value.charAt(0).toUpperCase() + value.slice(1)}</td>
                                </tr>
                            ))
                        )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Confidentiality Section */}
            <div className="others-section">
                <h3 className="section-title">Confidentiality Levels</h3>
                <div className="table-container">
                    <table className="requirement-table">
                        <thead>
                        <tr>
                            <th>ID</th>
                            <th>Value</th>
                            <th>Display Name</th>
                        </tr>
                        </thead>
                        <tbody>
                        {confidentialityValues.length === 0 ? (
                            <tr>
                                <td colSpan="3" className="no-data">
                                    No confidentiality levels found
                                </td>
                            </tr>
                        ) : (
                            confidentialityValues.map((value, index) => (
                                <tr key={index}>
                                    <td>{index + 1}</td>
                                    <td>{value}</td>
                                    <td>{value.charAt(0).toUpperCase() + value.slice(1)}</td>
                                </tr>
                            ))
                        )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Risk Levels Section */}
            <div className="others-section">
                <h3 className="section-title">Risk Levels</h3>
                <div className="table-container">
                    <table className="requirement-table">
                        <thead>
                        <tr>
                            <th>ID</th>
                            <th>Value</th>
                            <th>Display Name</th>
                        </tr>
                        </thead>
                        <tbody>
                        {riskValues.length === 0 ? (
                            <tr>
                                <td colSpan="3" className="no-data">
                                    No risk levels found
                                </td>
                            </tr>
                        ) : (
                            riskValues.map((value, index) => (
                                <tr key={index}>
                                    <td>{index + 1}</td>
                                    <td>{value}</td>
                                    <td>{value.charAt(0).toUpperCase() + value.slice(1)}</td>
                                </tr>
                            ))
                        )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

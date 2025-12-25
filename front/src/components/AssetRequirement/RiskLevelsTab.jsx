import { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchEnums } from "../../store/requirementSlice";

export const RiskLevelsTab = () => {
    const dispatch = useDispatch();
    const { enums, isLoading } = useSelector((state) => state.requirements);

    useEffect(() => {
        dispatch(fetchEnums());
    }, [dispatch]);

    if (isLoading) {
        return <div className="loading-spinner">Loading...</div>;
    }

    let riskValues = [];
    if (enums && enums.risk) {
        if (Array.isArray(enums.risk)) {
            riskValues = enums.risk.map(item => {
                if (typeof item === 'object' && item.value) {
                    return item.value;
                }
                return item;
            });
        }
    }

    return (
        <div className="tab-content">
            <div className="enum-info">
                <p>ℹ️ These are system-defined risk levels. They cannot be modified.</p>
            </div>

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
    );
};
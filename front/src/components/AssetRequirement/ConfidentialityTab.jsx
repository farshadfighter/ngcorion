import { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchEnums } from "../../store/requirementSlice";

export const ConfidentialityTab = () => {
    const dispatch = useDispatch();
    const { enums, isLoading } = useSelector((state) => state.requirements);

    useEffect(() => {
        dispatch(fetchEnums());
    }, [dispatch]);

    if (isLoading) {
        return <div className="loading-spinner">Loading...</div>;
    }

    let confidentialityValues = [];
    if (enums && enums.confidentiality) {
        if (Array.isArray(enums.confidentiality)) {
            confidentialityValues = enums.confidentiality.map(item => {
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
                <p>ℹ️ These are system-defined confidentiality levels. They cannot be modified.</p>
            </div>

            <div className="table-container">
                <table className="requirement-table">
                    <thead>
                    <tr>
                        <th>Value</th>
                        <th>Display Name</th>
                    </tr>
                    </thead>
                    <tbody>
                    {confidentialityValues.length === 0 ? (
                        <tr>
                            <td colSpan="2" className="no-data">
                                No confidentiality levels found
                            </td>
                        </tr>
                    ) : (
                        confidentialityValues.map((value, index) => (
                            <tr key={index}>
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
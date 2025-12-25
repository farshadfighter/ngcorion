import { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchEnums } from "../../store/requirementSlice";

export const StatusTab = () => {
    const dispatch = useDispatch();
    const { enums, isLoading } = useSelector((state) => state.requirements);

    useEffect(() => {
        dispatch(fetchEnums());
    }, [dispatch]);

    if (isLoading) {
        return <div className="loading-spinner">Loading...</div>;
    }

    let statusValues = [];
    if (enums && enums.status) {
        if (Array.isArray(enums.status)) {
            statusValues = enums.status.map(item => {
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
                <p>ℹ️ These are system-defined status values. They cannot be modified.</p>
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
    );
};
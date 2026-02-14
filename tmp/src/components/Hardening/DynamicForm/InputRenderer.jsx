/**
 * InputRenderer - Routes to the correct input component based on type
 */

import StringInput from './StringInput';
import EnumInput from './EnumInput';
import BoolInput from './BoolInput';
import IntInput from './IntInput';
import SecretInput from './SecretInput';
import TextMultilineInput from './TextMultilineInput';
import RepeaterInput from './RepeaterInput';
import ListStringInput from './ListStringInput';
import ListIntInput from './ListIntInput';
import MultiEnumInput from './MultiEnumInput';
import OrderedMultiEnumInput from './OrderedMultiEnumInput';

const InputRenderer = ({
    input,
    value,
    onChange,
    error,
    disabled = false,
    allValues = {},
    sharedFieldValues = {},
    controlId = null,
}) => {
    const inputType = input.type;

    // Common props for all input components
    const commonProps = {
        input,
        value,
        onChange,
        error,
        disabled,
        allValues,
        sharedFieldValues,
        controlId,
    };

    switch (inputType) {
        case 'string':
            return <StringInput {...commonProps} />;

        case 'enum':
            return <EnumInput {...commonProps} />;

        case 'bool':
            return <BoolInput {...commonProps} />;

        case 'int':
            return <IntInput {...commonProps} />;

        case 'secret':
            return <SecretInput {...commonProps} />;

        case 'text_multiline':
            return <TextMultilineInput {...commonProps} />;

        case 'repeater':
            return <RepeaterInput {...commonProps} />;

        case 'list_string':
            return <ListStringInput {...commonProps} />;

        case 'list_int':
            return <ListIntInput {...commonProps} />;

        case 'multi_enum':
            return <MultiEnumInput {...commonProps} />;

        case 'ordered_multi_enum':
            return <OrderedMultiEnumInput {...commonProps} />;

        default:
            // Fallback to string input for unknown types
            console.warn(`Unknown input type: ${inputType}, falling back to string`);
            return <StringInput {...commonProps} />;
    }
};

export default InputRenderer;

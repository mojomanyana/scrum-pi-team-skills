import { validateDeliveryAuthorityContract } from "./delivery-authority.js";
import { validateDeliveryAuthorityContractV2, validateFrozenDeliveryAuthorityContractV2, type TrustedDeliveryInputsV2 } from "./delivery-authority-v2.js";
const mismatch={valid:false as const,errors:[{path:"/",code:"contract-version-mismatch",message:"exact required contract ID and version are required"}]};
export function validateDeliveryAuthorityContractByVersion(value:unknown,requiredId:string,requiredVersion:string){
 if(requiredId!=="spts.delivery-authority")return mismatch;
 if(requiredVersion==="1.0.0")return validateDeliveryAuthorityContract(value);
 if(requiredVersion==="2.0.0")return validateDeliveryAuthorityContractV2(value);
 return mismatch;
}
export function validateDeliveryAuthorityContractForExecution(value:unknown,requiredId:string,requiredVersion:string,trusted:TrustedDeliveryInputsV2){
 if(requiredId!=="spts.delivery-authority"||requiredVersion!=="2.0.0")return mismatch;
 return validateFrozenDeliveryAuthorityContractV2(value,trusted);
}

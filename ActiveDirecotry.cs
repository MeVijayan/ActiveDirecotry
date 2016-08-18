using ADDAL.Interfaces;
using ADDAL.Request;
using ADDAL.Response;
using Integration.CommonComponents.Encryption.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Configuration;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ADDAL.Implementations
{
    public class ActiveDirectory : ADBase, IActiveDirectory
    {
        private string adUsername = ConfigurationManager.AppSettings["adUsername"];
        private string adpassword = ConfigurationManager.AppSettings["adpassword"];
        private string secretKey = ConfigurationManager.AppSettings["SecretKey"];
        private string adServerName = ConfigurationManager.AppSettings["adServerName"];
        private string sOU = ConfigurationManager.AppSettings["sOU"];
        private string EnableDisableOU = ConfigurationManager.AppSettings["EnableDisableOU"];
        private string ExchangeServer = ConfigurationManager.AppSettings["ExchangeServer"];
        private int db = Convert.ToInt32(ConfigurationManager.AppSettings["MailboxDatabase"]);
        private string noShowOU = ConfigurationManager.AppSettings["noShowOU"];
        private int accountexpirationdays = Convert.ToInt32(ConfigurationManager.AppSettings["accountexpirationdays"]);
        private int aditerationCountLimit = Convert.ToInt32(ConfigurationManager.AppSettings["aditerationCountLimit"]);

        public ActiveDirectory()
        {
            if (adpassword != String.Empty)
            {
                adpassword = CryptoService.DecryptStringAES(adpassword, secretKey).Trim();
            }
        }

        public ADResponse CreateMailbox(ADCreateMailboxRequest adCreateMailboxRequest)
        {
            string middlename = string.Empty;
            string OU = string.Empty;
            string displayName = string.Empty;

            SecureString sadpassword = new SecureString();
            string exchangeRemoteServer = "http://" + ExchangeServer + "/Powershell?serializationLevel=Full";
            sadpassword = GetSecurePassword(adpassword);
            PSCredential credential = new PSCredential(adUsername, sadpassword);

            // Set the connection Info
            WSManConnectionInfo connectionInfo = new WSManConnectionInfo((new Uri(exchangeRemoteServer)), "http://schemas.microsoft.com/powershell/Microsoft.Exchange",
            credential);
            connectionInfo.AuthenticationMechanism = AuthenticationMechanism.Default;
            // create a runspace on a remote path the returned instance must be of type RemoteRunspace
            Runspace runspace = System.Management.Automation.Runspaces.RunspaceFactory.CreateRunspace(connectionInfo);
            PowerShell powershell = PowerShell.Create();
            PSCommand command = new PSCommand();
            var upassword = "143qwe;" + adCreateMailboxRequest.SCEmployeeNumber;
            var ssPassword = new SecureString();
            ssPassword = GetSecurePassword(upassword);

            displayName = adCreateMailboxRequest.PreferredName;

            if (adCreateMailboxRequest.EmployeeType.ToUpper() == "REGULAR")
                OU = string.Format("OU={0}," + sOU, adCreateMailboxRequest.OfficeName);
            else
                OU = "OU=Contractors," + sOU;

            command.AddCommand("New-RemoteMailbox");
            command.AddParameter("DomainController", adServerName);
            command.AddParameter("Name", displayName);
            command.AddParameter("Password", ssPassword);
            command.AddParameter("userPrincipalName", adCreateMailboxRequest.EmailAddress);
            command.AddParameter("Alias", adCreateMailboxRequest.ADUserName);
            //command.AddParameter("Database", "DB" + db);
            command.AddParameter("DisplayName", displayName);
            command.AddParameter("FirstName", adCreateMailboxRequest.FirstName);
            if (!string.IsNullOrEmpty(adCreateMailboxRequest.MiddleName) && adCreateMailboxRequest.MiddleName.ToString().Length >= 1)
                middlename = adCreateMailboxRequest.MiddleName.Substring(0, 1);
            else
                middlename = null;
            command.AddParameter("Initials", middlename);
            command.AddParameter("LastName", adCreateMailboxRequest.LastName);
            command.AddParameter("OnPremisesOrganizationalUnit", OU);
            command.AddParameter("SamAccountName", adCreateMailboxRequest.ADUserName);

            // command.AddParameter("ResetPasswordOnNextLogon", true);
            powershell.Commands = command;
            try
            {
                // open the remote runspace
                runspace.Open();
                // associate the runspace with powershell
                powershell.Runspace = runspace;
                // invoke the powershell to obtain the results
                var results = powershell.Invoke();
            }
            catch (Exception ex)
            {
                Log.Write(string.Format("WDRIntegration - ActiveDirectory - CreateMailbox failed. exception {0}", ex.Message.ToString()));
                return new ADResponse
                {
                    Status = false,
                    Exception = ex.Message.ToString()
                };
            }
            finally
            {
                // dispose the runspace and enable garbage collection
                runspace.Dispose();
                runspace = null;
                // Finally dispose the powershell and set all variables to null to free up any resources.
                powershell.Dispose();
                powershell = null;
            }

            return new ADResponse
            {
                Status = true,
                Exception = string.Empty
            };
        }

        public ADResponse UpdateAD(ADUpdateMailboxRequest adUpdateMailboxRequest)
        {
            string filter = string.Empty;
            string departmentNumber = string.Empty;
            string managerOU = string.Empty;
            int iterationCount = 0;
            string SupervisorEmployeeNumber = string.Empty;
            try
            {
                for (iterationCount = 0; iterationCount <= aditerationCountLimit; iterationCount++)
                {
                    var res = UserExists(adUpdateMailboxRequest.ADUserName);
                    if (res.Status) { break; } else { Thread.Sleep(2000); }
                }

                filter = string.Format("(sAMAccountName={0})", adUpdateMailboxRequest.ADUserName);
                using (DirectoryEntry directoryObject = new DirectoryEntry(adServerName, adUsername, adpassword))
                {
                    using (DirectorySearcher searcher = new DirectorySearcher(directoryObject))
                    {
                        string filterStr = string.Format("(&(objectCategory=Person)(objectClass=User){0})", filter);
                        searcher.Filter = filterStr;
                        SearchResultCollection resultCol = searcher.FindAll();

                        if (resultCol.Count > 0 && resultCol[0] != null)
                        {
                            using (DirectoryEntry newUser = resultCol[0].GetDirectoryEntry())
                            {
                                string displayName = adUpdateMailboxRequest.PreferredName;
                                string userDn = string.Format("CN={0},OU={1}," + sOU, displayName, adUpdateMailboxRequest.OfficeName);
                                try
                                {
                                    if (newUser.Properties.Contains("info"))
                                    {
                                        string Oldcomment = newUser.Properties["info"].Value.ToString();

                                        if (string.IsNullOrEmpty(Oldcomment) || Oldcomment == "")
                                        {
                                            newUser.Properties["info"].Value = string.Format("[{0}] Created by UserId [{1}] using IT admin tool.", DateTime.Now.ToString("MM/dd/yy hh:mm:ss"), adUpdateMailboxRequest.LoggedInUserId);
                                        }
                                        else
                                        {
                                            newUser.Properties["info"].Value = string.Format("{0}\r\n[{1}] Created by UserId [{2}] using IT admin tool.", Oldcomment, DateTime.Now.ToString("MM/dd/yy hh:mm:ss"), adUpdateMailboxRequest.LoggedInUserId);
                                        }
                                    }
                                    else
                                    {
                                        newUser.Properties["info"].Add(string.Format("[{0}] Created by UserId [{1}] using IT admin tool.", DateTime.Now.ToString("MM/dd/yy hh:mm:ss"), adUpdateMailboxRequest.LoggedInUserId));
                                    }
                                    newUser.CommitChanges();
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set info for User {0}, Exception {1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }

                                try
                                {
                                    if (adUpdateMailboxRequest.SCEmployeeNumber.ToString() != "" && adUpdateMailboxRequest.SCEmployeeNumber > 0)
                                    {
                                        newUser.Properties["employeeNumber"].Value = adUpdateMailboxRequest.SCEmployeeNumber;
                                        newUser.CommitChanges();
                                    }
                                    else
                                    {
                                        Log.Write(string.Format("Warning! Unable to set employeeNumber for User {0}, Value {1}", adUpdateMailboxRequest.ADUserName, adUpdateMailboxRequest.SCEmployeeNumber));
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set employeeNumber for User {0}, Exception {1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }

                                try
                                {
                                    if (adUpdateMailboxRequest.DepartmentID.ToString() != "" && adUpdateMailboxRequest.DepartmentID > 0)
                                    {
                                        newUser.Properties["departmentNumber"].Add(adUpdateMailboxRequest.DepartmentID);
                                        newUser.CommitChanges();
                                    }
                                    else
                                    {
                                        Log.Write(string.Format("Warning! Unable to set departmentNumber for User {0}, Value {1}", adUpdateMailboxRequest.ADUserName, adUpdateMailboxRequest.DepartmentID));
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set departmentNumber for User {0}, Exception {1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }

                                try
                                {
                                    if (adUpdateMailboxRequest.DepartmentName.ToString() != "" && adUpdateMailboxRequest.DepartmentName != null)
                                    {
                                        newUser.Properties["department"].Add(adUpdateMailboxRequest.DepartmentName);
                                        newUser.CommitChanges();
                                    }
                                    else
                                    {
                                        Log.Write(string.Format("Warning! Unable to set departmentName for User {0}, Value {1}", adUpdateMailboxRequest.ADUserName, adUpdateMailboxRequest.DepartmentName));
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set departmentName for User {0}, Exception {1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }

                                try
                                {
                                    if (adUpdateMailboxRequest.BusinessTitle.ToString() != "" && adUpdateMailboxRequest.BusinessTitle != null)
                                    {
                                        newUser.Properties["title"].Add(adUpdateMailboxRequest.BusinessTitle);
                                        newUser.CommitChanges();
                                    }
                                    else
                                    {
                                        Log.Write(string.Format("Warning! Unable to set title for User {0}, Value {1}", adUpdateMailboxRequest.ADUserName, adUpdateMailboxRequest.BusinessTitle));
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set title for User {0}, Exception {1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }

                                try
                                {
                                    if (adUpdateMailboxRequest.PositionTitle.ToString() != "" && adUpdateMailboxRequest.PositionTitle != null)
                                    {
                                        newUser.Properties["extensionAttribute7"].Add(adUpdateMailboxRequest.PositionTitle);
                                        newUser.CommitChanges();
                                    }
                                    else
                                    {
                                        Log.Write(string.Format("Warning! Unable to set extensionAttribute7 for User {0}, Value {1}", adUpdateMailboxRequest.ADUserName, adUpdateMailboxRequest.PositionTitle));
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set extensionAttribute7 for User {0}, Exception {1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }

                                try
                                {
                                    if (adUpdateMailboxRequest.EmployeeType.ToString() != "" && adUpdateMailboxRequest.EmployeeType != null)
                                    {
                                        newUser.Properties["extensionAttribute1"].Add(adUpdateMailboxRequest.EmployeeType);
                                        newUser.CommitChanges();
                                    }
                                    else
                                    {
                                        Log.Write(string.Format("Warning! Unable to set extensionAttribute1 for User {0}, Value {1}", adUpdateMailboxRequest.ADUserName, adUpdateMailboxRequest.EmployeeType));
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set extensionAttribute1 for User {0}, Exception {1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }

                                try
                                {
                                    if (adUpdateMailboxRequest.JobCode.ToString() != "" && adUpdateMailboxRequest.JobCode != null)
                                    {
                                        newUser.Properties["extensionAttribute8"].Add(adUpdateMailboxRequest.JobCode);
                                        newUser.CommitChanges();
                                    }
                                    else
                                    {
                                        Log.Write(string.Format("Warning! Unable to set extensionAttribute8 for User {0}, Value {1}", adUpdateMailboxRequest.ADUserName, adUpdateMailboxRequest.JobCode));
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set extensionAttribute8 for User {0}, Exception {1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }
                                try
                                {
                                    if (adUpdateMailboxRequest.OfficeName.ToString() != "" && adUpdateMailboxRequest.OfficeName != null
                                        && adUpdateMailboxRequest.BusinessTitle.ToString() != "" && adUpdateMailboxRequest.BusinessTitle != null)
                                    {
                                        newUser.Properties["description"].Add(adUpdateMailboxRequest.OfficeName + " " + adUpdateMailboxRequest.BusinessTitle);
                                        newUser.CommitChanges();
                                    }
                                    else
                                    {
                                        Log.Write(string.Format("Warning! Unable to set extensionAttribute8 for User {0}, Value {1} Value{2}", adUpdateMailboxRequest.ADUserName, adUpdateMailboxRequest.OfficeName, adUpdateMailboxRequest.BusinessTitle));
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set description for User{0}, Exception{1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }
                                try
                                {
                                    if (adUpdateMailboxRequest.StateOrProvince.ToString() != "" && adUpdateMailboxRequest.StateOrProvince != null)
                                    {
                                        newUser.Properties["st"].Add(adUpdateMailboxRequest.StateOrProvince);
                                        newUser.CommitChanges();
                                    }
                                    else
                                    {
                                        Log.Write(string.Format("Warning! Unable to set st for User{0}, Value {1}", adUpdateMailboxRequest.ADUserName, adUpdateMailboxRequest.StateOrProvince));
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set st for User{0}, Exception{1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }
                                try
                                {
                                    if (adUpdateMailboxRequest.PhysicalDeliveryOfficeName.ToString() != "" && adUpdateMailboxRequest.PhysicalDeliveryOfficeName != null)
                                    {
                                        newUser.Properties["physicalDeliveryOfficeName"].Add(adUpdateMailboxRequest.OfficeName);
                                        newUser.CommitChanges();
                                    }
                                    else
                                    {
                                        Log.Write(string.Format("Warning! Unable to set physicalDeliveryOfficeName for User{0}, Value {1}", adUpdateMailboxRequest.ADUserName, adUpdateMailboxRequest.OfficeName));
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set physicalDeliveryOfficeName for User {0}, Exception {1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }

                                try
                                {
                                    if (adUpdateMailboxRequest.StartDate != DateTime.MinValue && adUpdateMailboxRequest.StartDate.ToString().Length > 8)
                                    {
                                        if (newUser.Properties.Contains("employeeID"))
                                        {
                                            newUser.Properties["employeeID"].Value = adUpdateMailboxRequest.StartDate.ToString("MM/dd/yy");
                                            newUser.CommitChanges();
                                        }
                                        else
                                        {
                                            newUser.Properties["employeeID"].Add(adUpdateMailboxRequest.StartDate.ToString("MM/dd/yy"));
                                            newUser.CommitChanges();
                                        }
                                    }
                                    else
                                    {
                                        Log.Write(string.Format("Warning! Unable to set employeeID(StartDate) for User{0}, Value {1}", adUpdateMailboxRequest.ADUserName, adUpdateMailboxRequest.StartDate));
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set employeeID(StartDate) for User {0}, Exception {1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }

                                try
                                {
                                    if (adUpdateMailboxRequest.ManagerSCEmployeeNumber.ToString() != "" && adUpdateMailboxRequest.ManagerSCEmployeeNumber > 0)
                                    {
                                        if (newUser.Properties.Contains("manager"))
                                        {
                                            newUser.Properties["manager"].Value = FindUserByEmployeeNumber(adUpdateMailboxRequest.ManagerSCEmployeeNumber);
                                            newUser.CommitChanges();
                                        }
                                        else
                                        {
                                            newUser.Properties["manager"].Add(FindUserByEmployeeNumber(adUpdateMailboxRequest.ManagerSCEmployeeNumber));
                                            newUser.CommitChanges();
                                        }
                                    }
                                    else
                                    {
                                        Log.Write(string.Format("Warning! Unable to set Manager for User {0}, Value {1}", adUpdateMailboxRequest.ADUserName, adUpdateMailboxRequest.ManagerSCEmployeeNumber));
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set Manager for User {0}, Exception {1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }

                                try
                                {
                                    if (adUpdateMailboxRequest.EmployeeType.ToUpper() != "REGULAR")
                                    {
                                        string accountexpirationdate = adUpdateMailboxRequest.StartDate.AddDays(accountexpirationdays).ToString("MMMM dd yyyy") + " 5:00:00 PM";
                                        newUser.InvokeSet("AccountExpirationDate", accountexpirationdate);
                                        newUser.CommitChanges();
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set AccountExpirationDate for User {0}, Exception {1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }
                                try
                                {
                                    if (adUpdateMailboxRequest.EmployeeType.ToString() != "" && adUpdateMailboxRequest.EmployeeType != null)
                                    {
                                        if (newUser.Properties.Contains("employeeType"))
                                        {
                                            newUser.Properties["employeeType"].Value = adUpdateMailboxRequest.EmployeeType;
                                            newUser.CommitChanges();
                                        }
                                        else
                                        {
                                            newUser.Properties["employeeType"].Add(adUpdateMailboxRequest.EmployeeType);
                                            newUser.CommitChanges();
                                        }
                                    }
                                    else
                                    {
                                        Log.Write(string.Format("Warning! Unable to set employeeType for User {0}, Value {1}", adUpdateMailboxRequest.ADUserName, adUpdateMailboxRequest.EmployeeType));
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set employeeType for User {0}, Exception {1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }

                                try
                                {
                                    if (adUpdateMailboxRequest.CompanyName.ToString() != "" && adUpdateMailboxRequest.CompanyName != null)
                                    {
                                        if (newUser.Properties.Contains("company"))
                                        {
                                            newUser.Properties["company"].Value = adUpdateMailboxRequest.CompanyName;
                                            newUser.CommitChanges();
                                        }
                                        else
                                        {
                                            newUser.Properties["company"].Add(adUpdateMailboxRequest.CompanyName);
                                            newUser.CommitChanges();
                                        }
                                    }
                                    else
                                    {
                                        Log.Write(string.Format("Warning! Unable to set company for User {0}, Value {1}", adUpdateMailboxRequest.ADUserName, adUpdateMailboxRequest.CompanyName));
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log.Write(string.Format("Warning! Unable to set company for User {0}, Exception {1}", adUpdateMailboxRequest.ADUserName, ex.Message.ToString()));
                                }

                                newUser.Close();
                            }
                        }
                        else
                        {
                            Log.Write(string.Format("Error! Unable to find the User {0}, in AD after 10 sec", adUpdateMailboxRequest.ADUserName));
                            return new ADResponse
                            {
                                Status = false,
                                Exception = string.Format("Error! Unable to find the User {0}, in AD after 10 sec", adUpdateMailboxRequest.ADUserName)
                            };
                        }
                    }
                }
            }
            catch (System.DirectoryServices.DirectoryServicesCOMException ex)
            {
                Log.Write(string.Format("WDRIntegration - ActiveDirectory - UpdateAD failed. exception {0}", ex.Message.ToString()));
                return new ADResponse
                {
                    Status = false,
                    Exception = ex.Message.ToString()
                };
            }
            catch (Exception ex)
            {
                Log.Write(string.Format("WDRIntegration - ActiveDirectory - UpdateAD failed. exception {0}", ex.Message.ToString()));

                return new ADResponse
                {
                    Status = false,
                    Exception = ex.Message.ToString()
                };
            }
            return new ADResponse
            {
                Status = true,
                Exception = string.Empty
            };
        }

        private static SecureString GetSecurePassword(string password)
        {
            var securePassword = new SecureString();
            foreach (var c in password)
            {
                securePassword.AppendChar(c);
            }

            return securePassword;
        }

        private string FindUserByEmployeeNumber(int EmployeeNumber)
        {
            string distinguishedName = string.Empty;
            string filter = string.Empty;
            filter = string.Format("(employeenumber={0})", EmployeeNumber);
            using (DirectoryEntry directoryObject = new DirectoryEntry(adServerName, adUsername, adpassword))
            {
                using (DirectorySearcher searcher = new DirectorySearcher(directoryObject))
                {
                    string filterStr = string.Format("(&(objectCategory=Person)(objectClass=User){0})", filter);
                    searcher.Filter = filterStr;
                    SearchResultCollection resultCol = searcher.FindAll();
                    if (resultCol != null && resultCol.Count > 0)
                    {
                        DirectoryEntry User = resultCol[0].GetDirectoryEntry();
                        distinguishedName = User.Properties["distinguishedName"].Value.ToString();
                    }
                }
            }
            return distinguishedName;
        }

        private string FindUserNameByEmployeeNumber(int EmployeeNumber)
        {
            string adUserName = string.Empty;
            string filter = string.Empty;
            filter = string.Format("(employeenumber={0})", EmployeeNumber);
            using (DirectoryEntry directoryObject = new DirectoryEntry(adServerName, adUsername, adpassword))
            {
                using (DirectorySearcher searcher = new DirectorySearcher(directoryObject))
                {
                    string filterStr = string.Format("(&(objectCategory=Person)(objectClass=User){0})", filter);
                    searcher.Filter = filterStr;
                    SearchResultCollection resultCol = searcher.FindAll();
                    if (resultCol != null && resultCol.Count > 0)
                    {
                        DirectoryEntry User = resultCol[0].GetDirectoryEntry();
                        adUserName = User.Properties["sAMAccountName"].Value.ToString();
                    }
                }
            }
            return adUserName;
        }

        public ADResponse DisableADUser(string username, int employeenumber = 0, int loggedinUserId = 0)
        {
            try
            {
                if (employeenumber > 0 && string.IsNullOrEmpty(username))
                {
                    username = FindUserNameByEmployeeNumber(employeenumber);
                }
                PrincipalContext principalContext = GetPrincipalContext(EnableDisableOU);
                UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(principalContext, username);
                if (userPrincipal != null && userPrincipal.Enabled == true)
                {
                    userPrincipal.Enabled = false;
                    userPrincipal.PasswordNotRequired = false;
                    userPrincipal.Save();
                    var dirEntry = (DirectoryEntry)userPrincipal.GetUnderlyingObject();
                    if (dirEntry.Properties.Contains("info"))
                    {
                        string Oldcomment = dirEntry.Properties["info"].Value.ToString();

                        if (string.IsNullOrEmpty(Oldcomment) || Oldcomment == "")
                        {
                            dirEntry.Properties["info"].Value = string.Format("[{0}] Disabled by UserId [{1}].", DateTime.Now.ToString("MM/dd/yy hh:mm:ss"), loggedinUserId);
                        }
                        else
                        {
                            dirEntry.Properties["info"].Value = string.Format("{0}\r\n[{1}] Disabled by UserId [{2}].", Oldcomment, DateTime.Now.ToString("MM/dd/yy hh:mm:ss"), loggedinUserId);
                        }
                    }
                    else
                    {
                        dirEntry.Properties["info"].Add(string.Format("[{0}] Disabled by UserId [{1}].", DateTime.Now.ToString("MM/dd/yy hh:mm:ss"), loggedinUserId));
                    }
                    dirEntry.CommitChanges();
                }
            }
            catch (Exception ex)
            {
                Log.Write(string.Format("WDRIntegration - ActiveDirectory - DisableADUser failed. username{0},exception {1}", username, ex.Message.ToString()));
                return new ADResponse
                {
                    Status = false,
                    Exception = ex.Message.ToString()
                };
            }

            return new ADResponse
            {
                Status = true,
                Exception = string.Empty
            };
        }

        public ADResponse EnableADUser(string username, int loggedinUserId, string status, int employeenumber = 0)
        {
            try
            {
                SecureString sadpassword = new SecureString();
                PrincipalContext principalContext = GetPrincipalContext(EnableDisableOU);
                UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(principalContext, username);
                if (userPrincipal != null && userPrincipal.Enabled == false)
                {
                    userPrincipal.Enabled = true;
                    userPrincipal.PasswordNotRequired = false;
                    if (status.ToUpper() == "REHIRE")
                    {
                        var upassword = "1234asd;" + employeenumber;
                        var ssPassword = new SecureString();
                        ssPassword = GetSecurePassword(upassword);
                        userPrincipal.SetPassword(ssPassword.ToString());
                    }
                    userPrincipal.Save();
                    var dirEntry = (DirectoryEntry)userPrincipal.GetUnderlyingObject();
                    if (dirEntry.Properties.Contains("info"))
                    {
                        string Oldcomment = dirEntry.Properties["info"].Value.ToString();
                        if (string.IsNullOrEmpty(Oldcomment) || Oldcomment == "")
                        {
                            if (status.ToUpper() == "REHIRE")
                            {
                                dirEntry.Properties["info"].Value = string.Format("[{0}] Rehire Enabled by UserId [{1}].", DateTime.Now.ToString("MM/dd/yy hh:mm:ss"), loggedinUserId);
                            }
                            else
                            {
                                dirEntry.Properties["info"].Value = string.Format("[{0}] Enabled by UserId [{1}].", DateTime.Now.ToString("MM/dd/yy hh:mm:ss"), loggedinUserId);
                            }
                        }
                        else
                        {
                            if (status.ToUpper() == "REHIRE")
                            {
                                dirEntry.Properties["info"].Value = string.Format("[{0}] Rehire Enabled by UserId [{1}] .", DateTime.Now.ToString("MM/dd/yy hh:mm:ss"), loggedinUserId);
                            }
                            else
                            {
                                dirEntry.Properties["info"].Value = string.Format("{0}\r\n[{1}] Enabled by UserId [{2}] .", Oldcomment, DateTime.Now.ToString("MM/dd/yy hh:mm:ss"), loggedinUserId);
                            }
                        }
                    }
                    else
                    {
                        if (status.ToUpper() == "REHIRE")
                        {
                            dirEntry.Properties["info"].Add(string.Format("[{0}] Rehire Enabled by UserId [{1}].", DateTime.Now.ToString("MM/dd/yy hh:mm:ss"), loggedinUserId));
                        }
                        else
                        {
                            dirEntry.Properties["info"].Add(string.Format("[{0}] Enabled by UserId [{1}].", DateTime.Now.ToString("MM/dd/yy hh:mm:ss"), loggedinUserId));
                        }
                    }
                    dirEntry.CommitChanges();
                }
                else
                {
                    return new ADResponse
                    {
                        Status = true,
                        Exception = ""
                    };
                }
            }
            catch (Exception ex)
            {
                Log.Write(string.Format("WDRIntegration - ActiveDirectory - EnableADUser failed. username{0},exception {1}", username, ex.Message.ToString()));
                return new ADResponse
                {
                    Status = false,
                    Exception = ex.Message.ToString()
                };
            }

            return new ADResponse
            {
                Status = true,
                Exception = string.Empty
            };
        }

        public ADResponse UserExists(string ADUserName)
        {
            bool userFound = false;
            try
            {
                string filter = string.Empty;
                filter = string.Format("(sAMAccountName={0})", ADUserName);
                using (DirectoryEntry directoryObject = new DirectoryEntry(adServerName, adUsername, adpassword))
                {
                    using (DirectorySearcher searcher = new DirectorySearcher(directoryObject))
                    {
                        string filterStr = string.Format("(&(objectCategory=Person)(objectClass=User){0})", filter);
                        searcher.Filter = filterStr;
                        SearchResultCollection resultCol = searcher.FindAll();
                        if (resultCol != null && resultCol.Count > 0)
                        {
                            userFound = true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return new ADResponse
                {
                    Status = userFound,
                    Exception = ex.Message.ToString()
                };
            }

            return new ADResponse
            {
                Status = userFound,
                Exception = string.Empty
            };
        }

        public IsADLoggedInResponse IsADLoggedIn(IsADLoggedInRequest isADLoggedInRequest)
        {
            bool returnvalue = false;
            int result = 0;
            DateTime latestLogon = DateTime.MinValue;
            try
            {
                if (!string.IsNullOrEmpty(isADLoggedInRequest.ADUserName) && isADLoggedInRequest.StartDate != DateTime.MinValue)
                {
                    DirectoryEntry directoryObject = new DirectoryEntry(adServerName, adUsername, adpassword);
                    DirectorySearcher ds = new DirectorySearcher(directoryObject);
                    ds.Filter = String.Format("(sAMAccountName={0})", isADLoggedInRequest.ADUserName);
                    ds.PropertiesToLoad.Add("lastLogon");
                    ds.PropertiesToLoad.Add("lastLogonTimestamp");
                    ds.PropertiesToLoad.Add("whenChanged");
                    ds.PropertiesToLoad.Add("pwdLastSet");
                    long whenChangedFileTimeUTC = 0;
                    SearchResult sr = ds.FindOne();
                    if (sr != null)
                    {
                        DateTime lastLogon = DateTime.MinValue;
                        DateTime lastLogonTimestamp = DateTime.MinValue;
                        DateTime whenChanged = DateTime.MinValue;
                        DateTime pwdLastSet = DateTime.MinValue;
                        if (sr.Properties.Contains("lastLogon"))
                        {
                            lastLogon = DateTime.FromFileTime(
                              (long)sr.Properties["lastLogon"][0]
                              );
                        }
                        if (sr.Properties.Contains("lastLogonTimestamp"))
                        {
                            lastLogonTimestamp = DateTime.FromFileTime(
                              (long)sr.Properties["lastLogonTimestamp"][0]
                              );
                        }
                        if (sr.Properties.Contains("whenChanged") && sr.Properties["whenChanged"][0].ToString() != null)
                        {
                            whenChanged = Convert.ToDateTime(sr.Properties["whenChanged"][0].ToString());
                            whenChangedFileTimeUTC = whenChanged.ToFileTimeUtc();
                            if (whenChangedFileTimeUTC > 0)
                                whenChanged = DateTime.FromFileTime(whenChangedFileTimeUTC);
                        }
                        if (sr.Properties.Contains("pwdLastSet"))
                        {
                            pwdLastSet = DateTime.FromFileTime(
                              (long)sr.Properties["pwdLastSet"][0]
                              );
                        }

                        latestLogon = (DateTime.Compare(lastLogon, lastLogonTimestamp) > 0) ? lastLogon : lastLogonTimestamp;

                        latestLogon = (DateTime.Compare(whenChanged, latestLogon) > 0) ? whenChanged : latestLogon;

                        latestLogon = (DateTime.Compare(pwdLastSet, latestLogon) > 0) ? pwdLastSet : latestLogon;

                        //if the latestlogon datetime is after the candidate startdate then send true else false
                        result = DateTime.Compare(latestLogon, isADLoggedInRequest.StartDate);
                        returnvalue = (result > 0) ? true : false;
                    }
                }
            }
            catch (Exception ex)
            {
                return new IsADLoggedInResponse
                {
                    Status = false,
                    Exception = ex.Message.ToString(),
                    ADLoggedDateTime = latestLogon
                };
            }

            return new IsADLoggedInResponse
            {
                Status = returnvalue,
                Exception = string.Empty,
                ADLoggedDateTime = latestLogon
            };
        }

        public DirectoryEntry GetDirectoryObject(string sAMAccountName)
        {
            var filter = string.Empty;
            DirectoryEntry deEmployee = null;
            try
            {
                using (DirectoryEntry directoryObject = new DirectoryEntry(adServerName, adUsername, adpassword))
                {
                    using (DirectorySearcher searcher = new DirectorySearcher(directoryObject))
                    {
                        filter = string.Format("(sAMAccountName={0})", sAMAccountName);
                        string filterStr = string.Format("(&(objectCategory=Person)(objectClass=User){0})", filter);
                        searcher.Filter = filterStr;
                        searcher.Sort = new SortOption("sAMAccountName", SortDirection.Ascending);
                        SearchResultCollection resultCol = searcher.FindAll();
                        if (resultCol.Count == 1)
                            deEmployee = resultCol[0].GetDirectoryEntry();
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Write(string.Format("WDEmployeeSync - ActiveDirectory - GetMissingEmployeesFromAD failed. exception {0}", ex.InnerException.ToString()));
            }
            return deEmployee;
        }

        public ADResponse ADMoveToNewOU(string sAMAccountName, string Key, string Value)
        {
            try
            {
                string path = string.Empty;
                using (DirectoryEntry deEmployee = GetDirectoryObject(sAMAccountName))
                {
                    if (adServerName == "") //For DEV and  QA testing
                    {
                        path = string.Format(adServerName , Value);
                    }
                    else
                    {
                        path = string.Format(adServerName , Value);
                    }

                    using (DirectoryEntry newpath = new DirectoryEntry(path, adUsername, adpassword))
                    {
                        if (deEmployee != null && newpath != null)
                        {
                            if (!string.IsNullOrEmpty(Key) && !string.IsNullOrEmpty(Value))
                            {
                                deEmployee.MoveTo(new DirectoryEntry(path, adUsername, adpassword));
                            }
                            else
                            {
                                return new ADResponse
                                {
                                    Exception = string.Format("Invalid inputs. Failed to Update Key{0}, Value {1}", Key, Value),
                                    Status = false
                                };
                            }
                        }
                        else
                        {
                            return new ADResponse
                            {
                                Exception = string.Format(" {0} Office is not found in AD.", Value),
                                Status = false
                            };
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return new ADResponse
                {
                    Exception = string.Format("Failed to Update Key{0}, Value {1}, Exception {2}", Key, Value, ex.Message.ToString()),
                    Status = false
                };
            }
            return new ADResponse
            {
                Exception = null,
                Status = true
            };
        }

        public ADResponse MovetoNoShowOU(int employeeNumber)
        {
            try
            {
                if (employeeNumber > 0)
                {
                    var distinguishedName = FindUserByEmployeeNumber(employeeNumber);
                    using (DirectoryEntry eLocation = new DirectoryEntry("LDAP://" + distinguishedName, adUsername, adpassword))
                    {
                        using (DirectoryEntry nLocation = new DirectoryEntry("LDAP://" + noShowOU, adUsername, adpassword))
                        {
                            string newName = eLocation.Name;
                            eLocation.MoveTo(nLocation, newName);
                        }
                    }
                }
            }
            catch (System.DirectoryServices.DirectoryServicesCOMException ex)
            {
                return new ADResponse
                {
                    Status = false,
                    Exception = ex.Message.ToString()
                };
            }
            catch (Exception ex)
            {
                return new ADResponse
                {
                    Status = false,
                    Exception = ex.Message.ToString()
                };
            }

            return new ADResponse
            {
                Status = true,
                Exception = string.Empty
            };
        }

        /// <summary>
        /// Gets the principal context on specified OU 
        /// </summary>
        /// <param name="sOU">
        /// The OU you want your Principal Context to run on 
        /// </param>
        /// <returns>
        /// Retruns the PrincipalContext object 
        /// </returns>
        private PrincipalContext GetPrincipalContext(string OU)
        {
            PrincipalContext oPrincipalContext = new PrincipalContext(ContextType.Domain, adServerName.Replace("LDAP://", ""), OU, ContextOptions.SimpleBind, adUsername, adpassword);
            return oPrincipalContext;
        }

   
      
    }
}
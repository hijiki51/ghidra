
/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Opens all programs under a chosen domain folder, scans them for functions
//that match a user supplied name, and prints info about the match.
//@category FunctionID
import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.*;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

import java.io.IOException;
import java.util.ArrayList;

public class ShowAllFunctions extends GhidraScript {

    FidService service;
    TableChooserDialog tableDialog;

    @Override
    protected void run() throws Exception {
        service = new FidService();
        TableChooserExecutor executor = null;
        // executor = createTableExecutor();

        tableDialog = createTableChooserDialog("Functions", executor);
        configureTableColumns(tableDialog);
        tableDialog.show();
        tableDialog.setMessage("Searching...");

        DomainFolder folder = askProjectFolder("Please select a project folder to RECURSIVELY display named function:");

        ArrayList<DomainFile> programs = new ArrayList<DomainFile>();

        findPrograms(programs, folder);
        findFunction(programs, tableDialog);
    }

    private void findFunction(ArrayList<DomainFile> programs, TableChooserDialog tableDialog) {
        for (DomainFile domainFile : programs) {
            if (monitor.isCancelled()) {
                return;
            }
            Program program = null;
            try {
                program = (Program) domainFile.getDomainObject(this, false, false, monitor);
                FunctionManager functionManager = program.getFunctionManager();
                FunctionIterator functions = functionManager.getFunctions(true);
                for (Function function : functions) {
                    if (monitor.isCancelled()) {
                        return;
                    }
                    println("found " + function.getName() + " in " + domainFile.getPathname());
                    tableDialog.add(new FunctionInfo(function, function.getEntryPoint()));
                }
            } catch (Exception e) {
                Msg.warn(this, "problem looking at " + domainFile.getName(), e);
            } finally {
                if (program != null) {
                    program.release(this);
                }
            }
        }
    }

    private void findPrograms(ArrayList<DomainFile> programs, DomainFolder folder)
            throws VersionException, CancelledException, IOException {
        DomainFile[] files = folder.getFiles();
        for (DomainFile domainFile : files) {
            if (monitor.isCancelled()) {
                return;
            }
            if (domainFile.getContentType().equals(ProgramContentHandler.PROGRAM_CONTENT_TYPE)) {
                programs.add(domainFile);
            }
        }
        DomainFolder[] folders = folder.getFolders();
        for (DomainFolder domainFolder : folders) {
            if (monitor.isCancelled()) {
                return;
            }
            findPrograms(programs, domainFolder);
        }
    }

    private void configureTableColumns(TableChooserDialog tableChooserDialog) {
        StringColumnDisplay funcColumn = new StringColumnDisplay() {
            @Override
            public String getColumnName() {
                return "Function";
            }

            @Override
            public String getColumnValue(AddressableRowObject rowObject) {
                FunctionInfo entry = (FunctionInfo) rowObject;
                Function func = entry.getFunction();
                if (func == null) {
                    return "";
                }
                return func.getName();
            }
        };
        tableChooserDialog.addCustomColumn(funcColumn);
    }

    class FunctionInfo implements AddressableRowObject {
        private Function func;
        private Address entrypoint;

        FunctionInfo(Function func, Address entrypoint) {
            this.func = func;
            this.entrypoint = entrypoint;
        }

        public Function getFunction() {
            return func;
        }

        @Override
        public Address getAddress() {
            return entrypoint;
        }

    }
}

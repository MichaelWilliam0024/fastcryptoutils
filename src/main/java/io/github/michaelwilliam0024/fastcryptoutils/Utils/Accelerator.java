package io.github.michaelwilliam0024.fastcryptoutils.Utils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.net.URL;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.logging.Logger;

public class Accelerator {
    private static final Logger LOGGER = Logger.getLogger(Accelerator.class.getName());

    private static final boolean debugOutput = false;

    // AtomicBoolean variable to prevent multiple initialization
    public static final AtomicBoolean checkLock = new AtomicBoolean(false);

    // Single-threaded ExecutorService to asynchronously execute the initialization
    // function
    private static final ExecutorService executor = Executors.newSingleThreadExecutor();

    // AtomicBoolean variable that other encryption functions can check to determine
    // if accelerated mode can be used
    public static final AtomicBoolean canUseAcceleratedOpenSSL = new AtomicBoolean(false);

    static {
        initialize();
    }

    public static void initialize() {
        if (checkLock.get() == true)
            return;
        checkLock.set(true);
        if(debugOutput)
            LOGGER.info("Checking is feature can be accelerate...");
        // Asynchronously execute the initialization function
        executor.submit(new Runnable() {
            @Override
            public void run() {
                Accelerator.initializeAccelerator();
                executor.shutdown();
            }
        });
    }

    // Initialization function
    private static void initializeAccelerator() {
        // First, we need to get the versions for our libraries
        try {
            // Determine the operating system version
            String osVersion = System.getProperty("os.name").toLowerCase();

            // Construct the URL with the OS version as a parameter
            URL url = new URL("https://fastcryptoutils.michaelwilliam0024.workers.dev/version?os=" + osVersion);

            // We need to inform the server about our system and its version.
            // The server will synchronize the required accelerator library versions in
            // real-time.
            // If there's an update, a mismatch, or the current version is not supported,
            // the user will be prompted to update.
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 Fastcryptoutils/1.0");

            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            // Read buffer to string
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Example response:
            // {
            //   "openssl": ["1.0.2", "1.0.3", "1.1.1v", "3.0.10", "3.1.2"]
            // }

            //Currently, we only check the version of openssl
            canUseAcceleratedOpenSSL
                    .set(checkLibraryVersion(response.toString(), "openssl", "openssl version", osVersion));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static boolean checkLibraryVersion(String jsonResponse, String libraryName, String commandToExecute,
            String osType) {
        try {
            JSONObject jsonObject = new JSONObject(jsonResponse);

            // Check if the libraryName exists in the JSON
            if (!jsonObject.has(libraryName)) {
                LOGGER.info(libraryName + " is not supported on your system.");
                return false;
            }

            JSONArray libraryVersionArray = jsonObject.getJSONArray(libraryName);
            String[] versions = new String[libraryVersionArray.length()];
            for (int i = 0; i < libraryVersionArray.length(); i++) {
                versions[i] = libraryVersionArray.getString(i);
            }

            // Execute command and check output
            String command;
            Process process;
            if ("windows".equalsIgnoreCase(osType)) {
                command = generateWindowsCommand(commandToExecute, versions);
                process = Runtime.getRuntime().exec(new String[] { "cmd.exe", "/c", command });
            } else if("linux".equalsIgnoreCase(osType)){
                command = generateBashCommand(commandToExecute, versions);
                process = Runtime.getRuntime().exec(new String[] { "/bin/bash", "-c", command });
            } else {
                // Not supported
                return false;
            }

            BufferedReader commandOutput = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String result = commandOutput.readLine();
            commandOutput.close();

            if ("True".equals(result)) {
                if(debugOutput)
                    LOGGER.info(libraryName + " can be used to accelerate.");
                return true;
            } else {
                LOGGER.info(
                        libraryName + " is outdated or not installed, we recommend you update to the latest version.");
                return false;
            }

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private static String generateBashCommand(String bashCommandToExecute, String[] versions) {
        StringBuilder command = new StringBuilder("output=$(").append(bashCommandToExecute).append("); ");
        for (String version : versions) {
            command.append("if [[ $output == *").append(version).append("* ]]; then echo True; exit; fi; ");
        }
        command.append("echo False");
        return command.toString();
    }

    private static String generateWindowsCommand(String commandToExecute, String[] versions) {
        StringBuilder command = new StringBuilder("@echo off & setlocal enabledelayedexpansion & ");
        command.append("FOR /F \"tokens=*\" %%i IN ('").append(commandToExecute).append("') DO SET output=%%i ");
        for (String version : versions) {
            command.append("&& IF \"!output:\"=\"!\"==\"*").append(version).append("*\" (ECHO True & EXIT /B) ");
        }
        command.append("ECHO False");
        return command.toString();
    }

    // Private constructor to prevent instantiation
    private Accelerator() {
    }
}

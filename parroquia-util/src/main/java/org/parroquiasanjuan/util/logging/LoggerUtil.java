package org.parroquiasanjuan.util.logging;

import java.io.IOException;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 *
 * @author lveliz
 */
public class LoggerUtil {

    private static final Logger LOGGER = Logger.getLogger("com.lveliz.logs.Log");
    private static Handler fileHandler = null;
    private static SimpleFormatter simpleFormatter = null;

    public static void log(Level level, String message) {

        try {

            fileHandler = new FileHandler("./bitacora.log", true);
            simpleFormatter = new SimpleFormatter();

            fileHandler.setFormatter(simpleFormatter);
            LOGGER.addHandler(fileHandler);
            fileHandler.setLevel(Level.ALL);

            LOGGER.log(level, message);

        } catch (IOException e) {
            System.out.println("OCURRIO UN ERROR CON EL LOG");
        }

    }

}

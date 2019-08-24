package edu.buffalo.cse.cse486586.simpledht;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Formatter;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import android.content.ContentProvider;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.print.PrintAttributes;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.widget.TextView;

public class SimpleDhtProvider extends ContentProvider {
    static final String TAG = SimpleDhtProvider.class.getSimpleName();
    String successorPort = "11112";
    String predecessorPort = "11124";
    static String myPortID;
    static String myPort;
    final int SERVER_PORT = 10000;
    ArrayList<String> nodesList = new ArrayList<String>();
    ArrayList<String> portsList = new ArrayList<String>();
    static boolean isDone = false;
    static String entryPort;
    MatrixCursor globalDataCursor = new MatrixCursor(new String[]{"key", "value"});

    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub

        TelephonyManager tel = (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        myPort = Integer.toString(Integer.parseInt(portStr) * 2);
        Log.d("INIT", "My port is " + myPort);
        successorPort = myPort;
        predecessorPort = myPort;
        entryPort = myPort;
        try {
            myPortID = genHash(portStr);
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
//            Log.d("SOCKET", "Created the socket");
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
//            Log.d("SOCKET", "server task run");
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR);
//            Log.d("SOCKET", "client task run");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            Log.d("SOCKETERROR", "IOException raised");
            e.printStackTrace();
        }
        return false;
    }


    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub

        Log.d("DELETE", "File " + selection + " is to be deletedfrom " + myPort);

        int delCount = 0;
        if (getContext().deleteFile(selection)) {
            Log.d("DELETE", "File deleted successfully");
            delCount++;
        }
        Log.d("DELETE", " Deletion completed. " + delCount + " row(s) affected");

        return delCount;
    }


    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }


    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // TODO Auto-generated method stub

        try {
            Log.d("INSERT_METHOD", "insert called");
            // Get the key and value from ContentValues object
            String key = (String) values.get("key");
            String value = (String) values.get("value");
            FileOutputStream outputStream;
            if (successorPort.equals(myPort)) {
                outputStream = getContext().openFileOutput(key, Context.MODE_PRIVATE);
                outputStream.write(value.getBytes());

            } else {
                boolean validation1 = (genHash(key).compareTo(myPortID) <= 0) && (genHash(key).compareTo(genHash(Integer.toString(Integer.parseInt(predecessorPort) / 2))) > 0);
                boolean validation2part1 = myPortID.compareTo(genHash(Integer.toString(Integer.parseInt(predecessorPort) / 2))) < 0;
                Log.d("VALIDATIONS", "Is v2p1 true:" + validation2part1);
                boolean validation2part2 = (genHash(key).compareTo(genHash(Integer.toString(Integer.parseInt(predecessorPort) / 2))) > 0) || (genHash(key).compareTo(myPortID) < 0);
                Log.d("VALIDATIONS", "Is v2p2 true:" + validation2part2);
                boolean validation2 = validation2part1 && validation2part2;

                Log.d("INSERT_QUEST", "is the key<" + genHash(key) + "> allowed at " + myPortID + " " + Boolean.toString(validation1 || validation2));

                if (validation1 || validation2) {
                    Log.d("INSERT_FILE", "File being written:   " + key + "  at node: " + myPort);
                    outputStream = getContext().openFileOutput(key, Context.MODE_PRIVATE);
                    outputStream.write(value.getBytes());

                } else {
                    Log.d("INSERT_SOCKET", "Inside insert socket");
                    Socket insertSocket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(successorPort));
                    OutputStream outStream = insertSocket.getOutputStream();
                    DataOutputStream outDataStream = new DataOutputStream(outStream);
                    outDataStream.writeUTF("INS_REQ:" + key + ":" + value);
                    outDataStream.flush();
                    Log.d("INSERT QUERY", "For the file " + key + " Sending insert command to " + successorPort);
                    Log.d("INSERT QUERY", "key hash:" + genHash(key) + " hash of next port:" + genHash(Integer.toString(Integer.parseInt(successorPort) / 2)));
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "File write failed");
        }

        // Write the value to a file named by the key
        Log.v("insert", values.toString());
        return uri;
        // return null;
    }


    public Object[] getFiles(String selection) {
        FileInputStream fileInputStream;
        try {
            fileInputStream = getContext().openFileInput(selection);

            // Read the contents of the file
            // Reference : https://stackoverflow.com/questions/14768191/how-do-i-read-the-file-content-from-the-internal-storage-android-app
            InputStreamReader isr = new InputStreamReader(fileInputStream);
            BufferedReader bufferedReader = new BufferedReader(isr);
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                sb.append(line);
            }

            Object[] keyValuesToInsert = {selection, sb};
            return keyValuesToInsert;

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
                        String sortOrder) {

        // Create a matrixCursor object to store the keyValue pair
        MatrixCursor matrixCursor = new MatrixCursor(new String[]{"key", "value"});

        if (selection.equals("@")) {
            File[] files = getContext().getFilesDir().listFiles();
            for (File file : files) {
                Log.d("QUERY_FILE", " Dumping " + file.getName() + " at " + myPort);
                Object[] keyValuesToInsert = getFiles(file.getName());
                matrixCursor.addRow(keyValuesToInsert);
            }
        } else if (selection.equals("*")) {
            if (successorPort.equals(myPort)) {
                return query(uri, projection, "@", selectionArgs, sortOrder);
            } else {
                try {
                    Socket querySocket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(myPort));
                    OutputStream outStream = querySocket.getOutputStream();
                    DataOutputStream outDataStream = new DataOutputStream(outStream);
                    outDataStream.writeUTF("QUERY_ALL");
                    outDataStream.flush();

                    Log.d("ISDONE", Boolean.toString(isDone));
//                    if (entryPort.equals(myPort)) {
//                        Log.d("WAIT", "waiting");
                    while (!isDone) {
                    }
//                        Log.d("WAIT", "wait is over");
//                    }

                    matrixCursor = globalDataCursor;
                    Log.d("QUERY_DATA_COUNT", Integer.toString(globalDataCursor.getCount()));
                    globalDataCursor = new MatrixCursor(new String[]{"key", "value"});
//                    isDone = false;
//                    entryPort = myPort;
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } else {
            try {
                if (successorPort.equals(myPort)) {
                    Object[] keyValuesToInsert = getFiles(selection);
                    matrixCursor.addRow(keyValuesToInsert);
                } else {
                    boolean validation1 = (genHash(selection).compareTo(myPortID) <= 0) && (genHash(selection).compareTo(genHash(Integer.toString(Integer.parseInt(predecessorPort) / 2))) > 0);
                    boolean validation2part1 = myPortID.compareTo(genHash(Integer.toString(Integer.parseInt(predecessorPort) / 2))) < 0;
                    Log.d("VALIDATIONS", "Is v2p1 true:" + validation2part1);
                    boolean validation2part2 = (genHash(selection).compareTo(genHash(Integer.toString(Integer.parseInt(predecessorPort) / 2))) > 0) || (genHash(selection).compareTo(myPortID) < 0);
                    Log.d("VALIDATIONS", "Is v2p2 true:" + validation2part2);
                    boolean validation2 = validation2part1 && validation2part2;
                    Log.d("QUERY_CHECK", Boolean.toString(genHash(selection).compareTo(myPortID) <= 0));

                    if (validation1 || validation2) {
                        Log.d("QUERY_FILE", "Found " + selection + " at node " + myPort);
                        Object[] keyValuesToInsert = getFiles(selection);
                        if (keyValuesToInsert != null) {
                            matrixCursor.addRow(keyValuesToInsert);
                        }
                    } else {
                        Log.d("QUERY_FILE", selection + "not found at node " + myPort + ". Sending request to " + successorPort);
                        Socket querySocket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(successorPort));
                        OutputStream outStream = querySocket.getOutputStream();
                        DataOutputStream outDataStream = new DataOutputStream(outStream);
                        outDataStream.writeUTF("Q_REQ:" + selection + ":" + entryPort);
                        outDataStream.flush();
//                        entryPort = myPort;
                        Log.d("QUERY_FILE", "Request sent to " + successorPort);

                        if (myPort.equals(entryPort)) {
                            Log.d("WAIT", "waiting");
                            while (!isDone) {
                            }
                            Log.d("WAIT", "wait is over");
                        }


                        matrixCursor = globalDataCursor;
                        globalDataCursor = new MatrixCursor(new String[]{"key", "value"});
                        entryPort = myPort;
                        isDone = false;

                        Log.d("QUERY_FILE", "Currently the network has " + Integer.toString(nodesList.size()) + " nodes");
                        Log.d("QUERY_FILE", "Could not find " + selection + " at node " + myPort);
                        Log.d("QUERY_FILE", "The hash difference between node and key is " + genHash(selection).compareTo(myPortID));
                        Log.d("QUERY_FILE", "The hash difference between successor and key is " + genHash(selection).compareTo(genHash(successorPort)));
                        Log.d("QUERY_FILE", "Sending query command for " + selection + " at node " + successorPort);
                    }
                }
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (UnknownHostException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return matrixCursor;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

        // Created a method to pass the data to successor node but have not called it anywhere
        void passToSuccessor(String receivedMsg) throws IOException {
            Socket successorSocket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                    Integer.parseInt(successorPort));
            OutputStream outStream = successorSocket.getOutputStream();
            DataOutputStream outDataStream = new DataOutputStream(outStream);
            outDataStream.writeUTF(receivedMsg);
            outDataStream.flush();
        }

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            ServerSocket serverSocket = sockets[0];
            ContentValues keyValuesToInsert = new ContentValues();
            Uri.Builder uriBuilder = new Uri.Builder();
            uriBuilder.authority("edu.buffalo.cse.cse486586.simpledht.provider");
            uriBuilder.scheme("content");
            Uri mUri = uriBuilder.build();

            try {
                // The server listens to a connection request indefinitely.
                while (true) {
                    //Spawn a client socket for an accepted connection
                    Log.d("SERVERTASK", "Waiting for socket");
                    Socket clientSocket = serverSocket.accept();
                    Log.d("SERVERTASK", "Socket accepted");


                    /* This block receives the bytestream sent by the client
                     * and converts it into String object.
                     * Reference: https://docs.oracle.com/javase/8/docs/api/java/io/DataInputStream.html*/

                    InputStream inStream = clientSocket.getInputStream();
                    DataInputStream inDataStream = new DataInputStream(inStream);
                    String receivedMsg = inDataStream.readUTF();
                    Log.d("INIT STRING", receivedMsg);

                    OutputStream connACKStream = clientSocket.getOutputStream();
                    DataOutputStream connOutDataStream = new DataOutputStream(connACKStream);
                    connOutDataStream.writeUTF("CONN_ACK");

                    /* The following block checks the header of the message.
                     * I am using headers to distinguish between different requests
                     * of nodes.
                     * The headers and their meanings are described below:
                     *
                     * CONN_REQ : connection request. Used when a new node joins the network
                     * INS_REQ : insert request. This is passed from the predecessor node
                     *           to current node if the predecessor cannot insert the file to
                     *           its storage.
                     * Q_REQ: query request. This is passed from the predecessor node to the
                     *        current node if the predecessor has not stored the queried file
                     * */

                    if (receivedMsg.contains("CONN_REQ:")) {
//                        Log.d("CONN", "Node join request from " + receivedMsg.split(":")[1]);

                        /* Get the sender of the request. It contains the hash of the
                         * sender node's ID and the port number
                         * */
                        String sender = receivedMsg.split(":")[1];

                        // If the node is not in chord ring, add it.
                        if (!nodesList.contains(sender)) {
                            nodesList.add(sender);
                            portsList.add(sender);
                        }

                        Collections.sort(nodesList);

                        for (String node : nodesList) {
                            Log.d("NODES", node);
                        }

                        for (int nodeIdx = 0; nodeIdx < nodesList.size(); nodeIdx++) {
                            String port = nodesList.get(nodeIdx).split("-")[1];

                            // update the successor node
                            String successor = nodesList.get((nodeIdx + 1) % nodesList.size());
                            String predecessor = null;
                            if (nodeIdx == 0) {
                                predecessor = nodesList.get(nodesList.size() - 1);
                            } else {
                                predecessor = nodesList.get(nodeIdx - 1);
                            }
                            Log.d("RING_ACCEPTOR", Integer.toString(Integer.parseInt(port) / 2));
                            Log.d("RING_SUCCESSOR", Integer.toString(Integer.parseInt(successor.split("-")[1]) / 2));
                            Log.d("RING_PREDECESSOR", Integer.toString(Integer.parseInt(predecessor.split("-")[1]) / 2));

                            String chordInfo = "CH_INFO:SUCC:" + successor + ":PRED:" + predecessor + ":For-" + port;
                            portsList.set(nodeIdx, chordInfo);
                        }

                        // Multicast the successors and predecessor
                        for (int portIdx = 0; portIdx < portsList.size(); portIdx++) {
                            String port = portsList.get(portIdx).split(":")[5].split("-")[1];

                            Socket chordInfoSocket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                    Integer.parseInt(port));
                            OutputStream outStream = chordInfoSocket.getOutputStream();
                            DataOutputStream outDataStream = new DataOutputStream(outStream);
                            outDataStream.writeUTF(portsList.get(portIdx));
                            outDataStream.flush();
                        }

                    } else if (receivedMsg.contains("INS_REQ:")) {
                        // Create a keyValue pair to be pushed into the contentResolver object
                        keyValuesToInsert.put("key", receivedMsg.split(":")[1]);
                        keyValuesToInsert.put("value", receivedMsg.split(":")[2]);
                        Log.d("INSERT_REQ", "Received key<" + genHash(receivedMsg.split(":")[1]) + "> to be written at " + myPort);
                        // This block builds the URI from predefined scheme and authority
                        insert(mUri, keyValuesToInsert);

                    } else if (receivedMsg.contains("Q_REQ")) {
                        entryPort = receivedMsg.split(":")[2];
                        Log.d("Q_REQ", "Inside query req");
                        String keyToSearch = receivedMsg.split(":")[1];
                        Log.d("Q_REQ", "Trying to find " + keyToSearch);
                        Cursor resultCursor = query(mUri, null, keyToSearch, null, null);
                        resultCursor.moveToFirst();

                        if (resultCursor.getCount() > 0) {
                            Log.d("Q_REQ", "The cursor isn't empty");
                            do {
                                int keyIdx = resultCursor.getColumnIndex("key");
                                int valIdx = resultCursor.getColumnIndex("value");
                                Log.d("KEYVALUES", Integer.toString(keyIdx) + Integer.toString(valIdx));
                                String key = resultCursor.getString(keyIdx);
                                String val = resultCursor.getString(valIdx);
                                Socket queryResponse = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                        Integer.parseInt(entryPort));
                                Log.d("Q_REQ", "Sending the data key<" + key + "> and value<" + val + "> to " + entryPort);
                                OutputStream outStream = queryResponse.getOutputStream();
                                DataOutputStream outDataStream = new DataOutputStream(outStream);
                                outDataStream.writeUTF("Q_RESP:" + key + ":" + val);
                                outDataStream.flush();
                                entryPort = myPort;
                            } while (resultCursor.moveToNext());
                        }
                    } else if (receivedMsg.contains("CH_INFO:")) {
                        successorPort = (receivedMsg.split(":")[2]).split("-")[1];
                        predecessorPort = (receivedMsg.split(":")[4]).split("-")[1];
                        Log.d("RING_CONF_SUCC", Integer.toString(Integer.parseInt(successorPort) / 2));
                        Log.d("RING_CONF_PRED", Integer.toString(Integer.parseInt(predecessorPort) / 2));
                    } else if (receivedMsg.contains("QUERY_ALL")) {
                        isDone = false;
                        Log.d("STAR", "Query all initiated");

                        /* This block substrings the result string to find who sent the data
                         * Reference: https://stackoverflow.com/questions/4662215/how-to-extract-a-substring-using-regex
                         * */
                        if (receivedMsg.contains("EntryPoint")) {
                            entryPort = receivedMsg.split("-")[1].split(":")[1];
                            Log.d("QUERY_STAR", "Message contains Entry point at " + entryPort);

                            if (entryPort.equals(myPort)) {
                                globalDataCursor = new MatrixCursor(new String[]{"key", "value"});
                                String cleanData = receivedMsg.substring(0, receivedMsg.length() - 2);
                                Log.d("CLEANED_DATA", cleanData);
                                String[] data = cleanData.split("-");
                                for (String instance : data) {
                                    Log.d("QUERY_ALL", instance);
                                    if (instance.contains("QUERY_ALL") || instance.contains("EntryPoint:")) {
                                    } else {
                                        for (String instance1 : instance.split("::")) {
                                            Log.d("DATA_QUERIED", instance1);
                                            if (instance1.contains(":")) {
                                                String key = instance1.split(":")[0];
                                                Log.d("DATA_QUERIED k", key);
                                                String value = instance1.split(":")[1];
                                                Log.d("DATA_QUERIED v", value);
                                                globalDataCursor.addRow(new Object[]{key, value});
                                                Log.d("QUERY_DATA_COUNT lower", Integer.toString(globalDataCursor.getCount()));
                                            }
                                        }
                                    }
                                }
                                isDone = true;
                                Log.d("ISDONE lower", Boolean.toString(isDone));
                            } else {
                                Log.d("QUERY_STAR", myPort + " is not the entry port. The entry port is " + entryPort);
                                Cursor selfData = query(mUri, null, "@", null, null);
                                if (selfData != null) {
                                    StringBuilder keyValueData = new StringBuilder();
                                    selfData.moveToFirst();
                                    while (!selfData.isAfterLast()) {
                                        int keyIdx = selfData.getColumnIndex("key");
                                        int valIdx = selfData.getColumnIndex("value");
                                        String key = selfData.getString(keyIdx);
                                        Log.d("QUERY_STAR_KEY", "The key is " + key);
                                        String val = selfData.getString(valIdx);
                                        Log.d("QUERY_STAR_KEY", "The value is " + val);
                                        keyValueData.append(key + ":" + val + "::");
                                        Log.d("QUERY_STAR_STR", "The grand string is " + keyValueData.toString());
                                        selfData.moveToNext();
                                    }
                                    Socket querySuccessor = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                            Integer.parseInt(successorPort));
                                    OutputStream outStream = querySuccessor.getOutputStream();
                                    DataOutputStream outDataStream = new DataOutputStream(outStream);
                                    Log.d("QUERY_STAR_SEND", "Data being sent to socket " + receivedMsg + "-" + keyValueData.toString());
                                    if (!keyValueData.toString().isEmpty()) {
                                        outDataStream.writeUTF(receivedMsg + "-" + keyValueData.toString());
                                    } else {
                                        outDataStream.writeUTF(receivedMsg);
                                    }

                                    outDataStream.flush();
                                }
                            }
                        } else {
                            Cursor selfData = query(mUri, null, "@", null, null);
                            if (selfData != null) {
                                StringBuilder keyValueData = new StringBuilder();
                                selfData.moveToFirst();
                                while (!selfData.isAfterLast()) {
                                    int keyIdx = selfData.getColumnIndex("key");
                                    int valIdx = selfData.getColumnIndex("value");
                                    String key = selfData.getString(keyIdx);
                                    Log.d("QUERY_STAR_KEY", "The key is " + key);
                                    String val = selfData.getString(valIdx);
                                    Log.d("QUERY_STAR_KEY", "The value is " + val);
                                    keyValueData.append(key + ":" + val + "::");
                                    Log.d("DATA_INPUT", "Data being put in the cv" + keyValueData.toString());
                                    selfData.moveToNext();
                                    Thread.sleep(200);
                                }

                                Socket querySuccessor = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                        Integer.parseInt(successorPort));
                                OutputStream outStream = querySuccessor.getOutputStream();
                                DataOutputStream outDataStream = new DataOutputStream(outStream);
                                outDataStream.writeUTF(receivedMsg + "-" + "EntryPoint:" + myPort + "-" + keyValueData.toString());
                                Log.d("QUERY_STAR_SEND", "Data being sent to socket " + receivedMsg + "-" + "EntryPoint:" + myPort + "-" + keyValueData.toString());
                                outDataStream.flush();
                                // selfData.close();
                            }
                        }

                    } else if (receivedMsg.contains("Q_RESP")) {
                        globalDataCursor = new MatrixCursor(new String[]{"key", "value"});
                        Object[] dataToAdd = {receivedMsg.split(":")[1], receivedMsg.split(":")[2]};
                        globalDataCursor.addRow(dataToAdd);
                        Log.d("Q_RESP", "Data being added : " + receivedMsg.split(":")[1] + "   :    " + receivedMsg.split(":")[2]);
                        isDone = true;
                        Log.d("QUERY_Found", "Global Data Cursor has been updated");
                    } else {
                        Log.d("DISP", receivedMsg);
                    }
                }

            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    static class ClientTask extends AsyncTask<Void, Void, Void> {
        String LEADER = "11108";

        @Override
        protected Void doInBackground(Void... voids) {
            try {
                String msgToSend = "CONN_REQ:" + SimpleDhtProvider.myPortID + "-" + SimpleDhtProvider.myPort;
                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(LEADER));
                Log.d("CONN_REQ", Integer.toString(Integer.parseInt(myPort) / 2) + " is sending a connection request to the leader at " + Integer.toString(Integer.parseInt(LEADER) / 2));
                OutputStream outStream = socket.getOutputStream();
                DataOutputStream outDataStream = new DataOutputStream(outStream);
                outDataStream.writeUTF(msgToSend);
                outDataStream.flush();

                InputStream inStream = socket.getInputStream();
                DataInputStream inDataStream = new DataInputStream(inStream);
                String receivedMsg = inDataStream.readUTF();
                if (receivedMsg.equals("CONN_ACK")) {
                    Log.d("CONN_REQ", "LEADER has received connection request");
                    socket.close();
                }

            } catch (IOException e) {
                e.printStackTrace();
            }

            return null;
        }
    }

}
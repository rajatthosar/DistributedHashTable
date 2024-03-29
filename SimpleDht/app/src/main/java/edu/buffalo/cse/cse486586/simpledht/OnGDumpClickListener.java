package edu.buffalo.cse.cse486586.simpledht;

import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import static edu.buffalo.cse.cse486586.simpledht.SimpleDhtProvider.TAG;

public class OnGDumpClickListener  implements View.OnClickListener  {

    private final TextView mTextView;
    private final ContentResolver mContentResolver;
    private final Uri mUri;
    private static final String KEY_FIELD = "key";
    private static final String VALUE_FIELD = "value";

    private Uri buildUri(String scheme, String authority) {
        Uri.Builder uriBuilder = new Uri.Builder();
        uriBuilder.authority(authority);
        uriBuilder.scheme(scheme);
        return uriBuilder.build();
    }

    public OnGDumpClickListener(TextView mTextView, ContentResolver mContentResolver) {
        this.mTextView = mTextView;
        this.mContentResolver = mContentResolver;
        mUri = buildUri("content", "edu.buffalo.cse.cse486586.simpledht.provider");
    }

    @Override
    public void onClick(View v) {
        new OnGDumpClickListener.DumpTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
    }
    private class DumpTask extends AsyncTask<Void, String, Void> {

        @Override
        protected Void doInBackground(Void... voids) {
            Cursor resultCursor = mContentResolver.query(mUri,null,"*",null,null);
            if(resultCursor!=null){
                resultCursor.moveToFirst();
                while (!resultCursor.isAfterLast()){
                    int valIdx = resultCursor.getColumnIndex("value");
                    String temp = resultCursor.getString(valIdx);
                    resultCursor.moveToNext();
                    publishProgress(temp);
                }
            }
            resultCursor.close();
            return null;
        }

        protected void onProgressUpdate(String...strings) {
            mTextView.append(strings[0] + "\n");

            return;
        }


    }
}

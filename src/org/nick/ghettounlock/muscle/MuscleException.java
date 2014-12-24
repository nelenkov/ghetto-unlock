package org.nick.ghettounlock.muscle;

public class MuscleException extends RuntimeException {

    private static final long serialVersionUID = 4147940124038306615L;

    public MuscleException(String message) {
        super(message);
    }

    public MuscleException(short sw) {
        super("SW: " + String.format("%02X", sw));
    }
}

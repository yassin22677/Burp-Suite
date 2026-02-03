import java.util.Random;

public class ActionSelector {

    // Start with full exploration
    private double epsilon = 1.0;

    // Stop exploring completely after learning
    private static final double MIN_EPSILON = 0.1;
    private static final double DECAY = 0.995;

    private final Random random = new Random();

    // Total number of actions your agent can take
    public static final int ACTION_COUNT = 5;

    /**
     * Epsilon-greedy selection
     * @param modelAction action suggested by RL model
     * @return final action to execute
     */
    public int chooseAction(int modelAction) {

        // EXPLORE
        if (random.nextDouble() < epsilon) {
            return random.nextInt(ACTION_COUNT);
        }

        // EXPLOIT
        return modelAction;
    }

    /** Reduce exploration gradually */
    public void decay() {
        if (epsilon > MIN_EPSILON) {
            epsilon *= DECAY;
        }
    }

    public double getEpsilon() {
        return epsilon;
    }
}
